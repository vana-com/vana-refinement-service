#!/bin/bash
curl http://0.0.0.0:8091/refine -X POST -H "Content-Type: application/json" -d '{
    "file_id": 22,
    "encryption_key": "0xb7692f02a565da52dd0e8422b835453a595c0dcab488e562cde95828a7b72a1a11c6c2dc137a14025b0a1fd9f5408f509262c681711e969bc73dd5e382d8f1fa1b",
    "refiner_id": 1,
    "env_vars": {
      "USER_EMAIL": "user123@gmail.com"
    }
}'