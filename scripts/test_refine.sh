#!/bin/bash
# curl https://a7df0ae43df690b889c1201546d7058ceb04d21b-8000.dstack-prod5.phala.network/refine -X POST -H "Content-Type: application/json" -d '{
curl localhost:8000/refine -X POST -H "Content-Type: application/json" -d '{
    "file_id": 1642435,
    "encryption_key": "0x261b08677b5235cd7eeb90602f235919e159c49de0503d9d5b40272dca43f323078a3b29e9bb15a7adb89568a474f40cbaff88793e9ca040c174b40f3ff36b2f1c",
    "refiner_id": 4,
    "env_vars": {
      "PINATA_API_KEY": "2004ceab5cfbe967d983",
      "PINATA_API_SECRET": "d3df7dbea4db02d0d8480b6571b083cbdd873f5fbb2e873da79ec952e4c42dfd"
    }
}'