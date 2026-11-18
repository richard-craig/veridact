"""Relying-party nonces in DynamoDB, shared by every authoriser instance.

Lambda runs many copies of the authoriser, so a nonce issued by one must be usable,
exactly once, by another. Consumption is a conditional delete: of two parallel replays
of the same presentation, DynamoDB lets exactly one delete succeed.

Table: partition key ``nonce`` (string), TTL attribute ``expires`` (epoch seconds).
"""

from __future__ import annotations

import re
import secrets
import time
from typing import Any, Callable

NONCE_RE = re.compile(r"^[0-9a-f]{32}$")


class DynamoNonceStore:
    def __init__(self, table: str, *, client: Any = None, ttl: float = 120.0,
                 clock: Callable[[], float] = time.time):
        if client is None:
            import boto3
            client = boto3.client("dynamodb")
        self.client = client
        self.table = table
        self.ttl = ttl
        self.clock = clock

    def issue(self) -> str:
        nonce = secrets.token_hex(16)
        self.client.put_item(
            TableName=self.table,
            Item={"nonce": {"S": nonce}, "expires": {"N": str(int(self.clock() + self.ttl))}},
            ConditionExpression="attribute_not_exists(nonce)",
        )
        return nonce

    def is_live(self, nonce: str) -> bool:
        # Only well-formed nonces reach DynamoDB, so a caller cannot make us read junk keys.
        if not isinstance(nonce, str) or not NONCE_RE.match(nonce):
            return False
        item = self.client.get_item(TableName=self.table, Key={"nonce": {"S": nonce}},
                                    ConsistentRead=True).get("Item")
        # DynamoDB TTL deletes lazily, so check expiry ourselves.
        return item is not None and int(item["expires"]["N"]) > self.clock()

    def consume(self, nonce: str) -> bool:
        if not isinstance(nonce, str) or not NONCE_RE.match(nonce):
            return False
        try:
            self.client.delete_item(
                TableName=self.table,
                Key={"nonce": {"S": nonce}},
                ConditionExpression="attribute_exists(nonce) AND expires > :now",
                ExpressionAttributeValues={":now": {"N": str(int(self.clock()))}},
            )
        except self.client.exceptions.ConditionalCheckFailedException:
            return False
        return True
