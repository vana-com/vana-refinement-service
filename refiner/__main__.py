import asyncio
import copy
import logging
import os
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

import vana
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware

from refiner.middleware.error_handler import error_handler_middleware
from refiner.middleware.log_request_id_handler import add_request_id_middleware, request_id_context
from refiner.models.models import RefinementRequest, RefinementResponse
from refiner.services import refine
from refiner.utils.config import add_args, check_config, default_config
from refiner.utils.logfilter import RequestIdFilter

load_dotenv()

from vana.logging import _logging
from vana.logging import logging as vana_logging

SHORT_LOG_FORMAT = "[%(request_id)s] | %(message)s"
LONG_LOG_FORMAT = "%(asctime)s | %(levelname)s | [%(request_id)s] | %(message)s"
formatter = _logging.Formatter(fmt=SHORT_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
long_formatter = _logging.Formatter(fmt=LONG_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

for handler in vana_logging._logger.handlers:
    handler.setFormatter(formatter)

original_logger = vana.logging._logger
original_logger.addFilter(RequestIdFilter())
vana.logging._logger = original_logger

logging.getLogger().addFilter(RequestIdFilter())
for handler in logging.getLogger().handlers:
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(long_formatter)

thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() * 2)


class Refiner:
    """
    Represents the Refiner service
    """

    @classmethod
    def check_config(cls, config: vana.Config):
        check_config(cls, config)

    @classmethod
    def add_args(cls, parser):
        add_args(cls, parser)

    @classmethod
    def config(cls):
        return default_config(cls)

    def __init__(self, config=None):
        self.config = self.config()
        if config:
            base_config = copy.deepcopy(config)
            self.config.merge(base_config)
        self.check_config(self.config)

        # Set up logging with the provided configuration and directory.
        vana.logging(config=self.config, logging_dir=self.config.full_path)

        self.wallet = vana.Wallet(config=self.config)
        self.chain_manager = vana.ChainManager(config=self.config)
        self.vana_client = vana.Client(config=self.config)

        # Serve NodeServer to enable external connections.
        max_workers = os.cpu_count() * 2 + 1
        self.config.node_server.verify_body_integrity = False
        self.node_server = ((vana.NodeServer(
            wallet=self.wallet,
            config=self.config,
            max_workers=max_workers
        ).serve(chain_manager=self.chain_manager)).start())

        # Refinement endpoint
        self.node_server.router.add_api_route(
            f"/refine",
            self.forward_refinement,
            methods=["POST"],
        )
        self.node_server.app.include_router(self.node_server.router)

        # Basic health check for docker container monitoring
        self.node_server.router.add_api_route(
            f"/",
            lambda: {"status": "ok"},
            methods=["GET"]
        )
        self.node_server.app.include_router(self.node_server.router)

        # Enable CORS
        self.node_server.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["OPTIONS", "GET", "POST"],
            allow_headers=["*"],
        )

        # Add error handling middleware
        self.node_server.app.middleware("http")(error_handler_middleware)
        self.node_server.app.middleware("http")(add_request_id_middleware)

        # Create asyncio event loop to manage async tasks.
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        # Instantiate runners
        self.should_exit: bool = False
        self.is_running: bool = False
        self.thread: threading.Thread = None
        self.lock = asyncio.Lock()

        # Check balance
        balance = self.chain_manager.get_balance(self.wallet.hotkey.address)
        if balance < 0.1 and self.config.environment == "production":
            vana.logging.error(
                f"Insufficient balance: {balance} VANA, please top up the wallet {self.wallet.hotkey.address}")
            exit(1)

        vana.logging.info(f"Running refiner on network: {self.config.chain.chain_endpoint}")
        vana.logging.info(self.config)

    async def forward_refinement(self, request: RefinementRequest) -> RefinementResponse:
        request_id = request_id_context.get()

        return await asyncio.get_event_loop().run_in_executor(
            thread_pool,
            refine,
            self.vana_client,
            request,
            request_id
        )

    async def run(self):
        """
        Initiates and manages the main loop for the refiner on the network.
        """
        self.sync()

        # This loop maintains the refiner's operations until intentionally stopped.
        try:
            while True:
                if self.should_exit:
                    break

                time.sleep(8)
                self.sync()

        # If someone intentionally stops the refiner, it'll safely terminate operations.
        except KeyboardInterrupt:
            if hasattr(self, 'node_server') and self.node_server:
                self.node_server.stop()
                self.node_server.unserve(dlp_uid=self.config.dlpuid, chain_manager=self.chain_manager)
            vana.logging.success("Refiner killed by keyboard interrupt.")
            exit()

        # In case of unforeseen errors, the refiner will log the error and continue operations.
        except Exception as err:
            vana.logging.error("Error during refinement", str(err))
            vana.logging.debug(traceback.print_exception(type(err), err, err.__traceback__))

    def sync(self):
        pass

    def run_in_background_thread(self):
        """
        Starts the refiner's operations in a background thread upon entering the context.
        This method facilitates the use of the refiner in a 'with' statement.
        """
        if not self.is_running:
            vana.logging.debug("Starting refiner in background thread.")
            self.should_exit = False
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()
            self.is_running = True
            vana.logging.debug("Started")

    def stop_run_thread(self):
        """
        Stops the refiner's operations that are running in the background thread.
        """
        if self.is_running:
            vana.logging.debug("Stopping refiner in background thread.")
            self.should_exit = True
            self.thread.join(5)
            self.is_running = False
            vana.logging.debug("Stopped")

    def __enter__(self):
        self.run_in_background_thread()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Stops the validator's background operations upon exiting the context.
        This method facilitates the use of the validator in a 'with' statement.

        Args:
            exc_type: The type of the exception that caused the context to be exited.
                      None if the context was exited without an exception.
            exc_value: The instance of the exception that caused the context to be exited.
                       None if the context was exited without an exception.
            traceback: A traceback object encoding the stack trace.
                       None if the context was exited without an exception.
        """
        if self.is_running:
            vana.logging.debug("Stopping validator in background thread.")
            self.should_exit = True
            self.thread.join(5)
            self.is_running = False
            vana.logging.debug("Stopped")


# poetry run python -m app
if __name__ == "__main__":
    # vana.trace()
    try:
        while True:
            try:
                refiner = Refiner()
                asyncio.run(refiner.run())
            except Exception as e:
                vana.logging.error(f"An error occurred: {str(e)}")
                vana.logging.error(traceback.format_exc())
                vana.logging.error("Restarting the refiner in 5 seconds...")
                time.sleep(5)
    finally:
        vana.logging.info("Refiner stopped.")
        sys.exit(0)
