#!/bin/bash
curl http://0.0.0.0:8091/refine -X POST -H "Content-Type: application/json" -d '{
    "file_id": 1642435,
    "encryption_key": "0x261b08677b5235cd7eeb90602f235919e159c49de0503d9d5b40272dca43f323078a3b29e9bb15a7adb89568a474f40cbaff88793e9ca040c174b40f3ff36b2f1c",
    "refiner_id": 4,
    "env_vars": {
      "PINATA_API_KEY": "xxx",
      "PINATA_API_SECRET": "yyy"
    }
}'