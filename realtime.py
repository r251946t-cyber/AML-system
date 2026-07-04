import json
import os
import uuid
from queue import Empty, Queue

from flask import Response

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

try:
    from kafka import KafkaProducer
except ImportError:  # pragma: no cover
    KafkaProducer = None


class RealtimeBroker:
    def __init__(self, app=None, socketio=None):
        self.app = app
        self.socketio = socketio
        self._subscribers = []
        self._redis_client = None
        self._redis_pubsub = None
        self._kafka_producer = None
        self._instance_id = str(uuid.uuid4())
        self._init_brokers()
        self._start_redis_listener()

    def _init_brokers(self):
        redis_url = os.environ.get("REDIS_URL")
        if redis_url and redis is not None:
            try:
                self._redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=0.5,
                    socket_timeout=0.5,
                )
                self._redis_client.ping()
            except Exception:
                self._redis_client = None

        kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
        if kafka_bootstrap and KafkaProducer is not None:
            try:
                self._kafka_producer = KafkaProducer(
                    bootstrap_servers=[server.strip() for server in kafka_bootstrap.split(",") if server.strip()],
                    api_version_auto_timeout_ms=500,
                    request_timeout_ms=1000,
                    max_block_ms=1000,
                    value_serializer=lambda value: json.dumps(value).encode("utf-8"),
                )
            except Exception:
                self._kafka_producer = None

    def _start_redis_listener(self):
        """Subscribe to Redis pub/sub for cross-instance event fan-out."""
        if self._redis_client is None:
            return
        try:
            import threading
            self._redis_pubsub = self._redis_client.pubsub(ignore_subscribe_messages=True)
            self._redis_pubsub.subscribe("aml-events")

            def _listen():
                for raw in self._redis_pubsub.listen():
                    if raw.get("type") != "message":
                        continue
                    try:
                        message = json.loads(raw["data"])
                        if message.get("publisher") == self._instance_id:
                            continue
                        self._local_deliver(message.get("event"), message.get("data"))
                    except Exception:
                        pass

            thread = threading.Thread(target=_listen, daemon=True)
            thread.start()
        except Exception:
            self._redis_pubsub = None

    def _local_deliver(self, event_name, payload):
        if not event_name:
            return
        message = {"event": event_name, "data": payload}
        delivered = set()
        app_subscribers = self.app.config.get("STREAM_SUBSCRIBERS", []) if self.app is not None else []
        for subscriber in list(self._subscribers) + list(app_subscribers):
            subscriber_id = id(subscriber)
            if subscriber_id in delivered:
                continue
            delivered.add(subscriber_id)
            try:
                subscriber.put_nowait(message)
            except Exception:
                pass
        if self.socketio is not None:
            try:
                self.socketio.emit(event_name, payload, broadcast=True)
            except Exception:
                pass

    def set_socketio(self, socketio):
        self.socketio = socketio

    def add_subscriber(self, queue):
        self._subscribers.append(queue)
        if self.app is not None:
            app_subscribers = self.app.config.setdefault("STREAM_SUBSCRIBERS", [])
            if queue not in app_subscribers:
                app_subscribers.append(queue)
        return queue

    def publish(self, event_name, payload):
        message = {"event": event_name, "data": payload, "publisher": self._instance_id}
        self._local_deliver(event_name, payload)

        # Persist events to Redis for recovery (if available)
        if self._redis_client is not None:
            try:
                # Store last 1000 events for replay on reconnection
                event_key = f"aml_events:history"
                self._redis_client.lpush(event_key, json.dumps(message))
                self._redis_client.ltrim(event_key, 0, 999)
                self._redis_client.expire(event_key, 3600)  # Keep for 1 hour
                # Also publish to pub/sub for real-time delivery
                self._redis_client.publish("aml-events", json.dumps(message))
            except Exception:
                pass

        if self._kafka_producer is not None:
            try:
                self._kafka_producer.send("aml-events", message)
            except Exception:
                pass

    def stream_response(self):
        queue = Queue()
        self.add_subscriber(queue)

        def generate():
            try:
                yield ": connected\n\n"
                while True:
                    try:
                        message = queue.get(timeout=1)
                    except Empty:
                        yield ": heartbeat\n\n"
                        continue
                    yield f"event: {message['event']}\n"
                    yield f"data: {json.dumps(message['data'])}\n\n"
            finally:
                if queue in self._subscribers:
                    self._subscribers.remove(queue)
                if self.app is not None:
                    app_subscribers = self.app.config.get("STREAM_SUBSCRIBERS", [])
                    if queue in app_subscribers:
                        app_subscribers.remove(queue)

        return Response(generate(), mimetype="text/event-stream")
