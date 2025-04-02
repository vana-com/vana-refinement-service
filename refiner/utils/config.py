import argparse
import os

import vana
from dotenv import load_dotenv

load_dotenv()


def check_config(cls, config: vana.Config):
    r"""Checks/validates the config namespace object."""
    vana.logging.check_config(config)


def add_args(cls, parser):
    """
    Adds relevant arguments to the parser for operation.
    """
    parser.add_argument(
        "--node.environment",
        type=str,
        help="The environment the node is running in (development, production).",
        default=os.getenv("ENVIRONMENT", "production"),
    )


def default_config(cls):
    """
    Returns the configuration object specific to this node.
    """
    parser = argparse.ArgumentParser()
    vana.Wallet.add_args(parser)
    vana.ChainManager.add_args(parser)
    vana.Client.add_args(parser)
    vana.NodeServer.add_args(parser)
    vana.logging.add_args(parser)
    cls.add_args(parser)
    return vana.Config(parser)
