"""
realtime.py — Real-time Event Broker Module

This module provides real-time event broadcasting for WebSocket/Redis/Kafka.
It handles cross-instance messaging, offline user queuing, and SSE streaming.

Classes:
    - RealtimeBroker: Real-time event broker for WebSocket/Redis/Kafka broadcasting
"""

import json
import os
import socket
import threading
import time
import uuid
from queue import Empty, Queue
from flask import Response

try:
    import redis
except ImportError:
    redis = None

try:
    from kafka import KafkaProducer
except ImportError:
    KafkaProducer = None


class RealtimeBroker:
    """Real-time event broker for WebSocket/Redis/Kafka broadcasting."""
    
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
        """Initialize Redis and Kafka connections."""
        redis_url = os.environ.get("REDIS_URL")
        if redis_url and redis is not None:
            try:
                # redis-py expects numeric socket option constants, not their
                # string names. Windows does not expose every Linux setting.
                keepalive_options = {}
                for option_name, value in (
                    ("TCP_KEEPIDLE", 1),
                    ("TCP_KEEPINTVL", 1),
                    ("TCP_KEEPCNT", 3),
                ):
                    option = getattr(socket, option_name, None)
                    if option is not None:
                        keepalive_options[option] = value
                self._redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2.0,
                    socket_timeout=2.0,
                    socket_keepalive=True,
                    socket_keepalive_options=keepalive_options or None,
                )
                self._redis_client.ping()
                if self.app:
                    self.app.logger.info(f"RealtimeBroker connected to Redis: {redis_url}")
            except Exception as e:
                if self.app:
                    self.app.logger.error(f"RealtimeBroker failed to connect to Redis: {e}")
                self._redis_client = None

        kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
        # Skip Kafka if not configured or set to localhost (won't work in cloud)
        if kafka_bootstrap and KafkaProducer is not None and "localhost" not in kafka_bootstrap and "127.0.0.1" not in kafka_bootstrap:
            try:
                self._kafka_producer = KafkaProducer(
                    bootstrap_servers=[server.strip() for server in kafka_bootstrap.split(",") if server.strip()],
                    api_version_auto_timeout_ms=100,
                    request_timeout_ms=200,
                    max_block_ms=200,
                    value_serializer=lambda value: json.dumps(value).encode("utf-8"),
                )
            except Exception:
                self._kafka_producer = None

    def _start_redis_listener(self):
        """Subscribe to Redis pub/sub for cross-instance event fan-out."""
        if self._redis_client is None:
            if self.app:
                self.app.logger.warning("Redis client not available, skipping Redis listener")
            return
        try:
            self._redis_pubsub = self._redis_client.pubsub(ignore_subscribe_messages=True)
            self._redis_pubsub.subscribe("aml-events")
            if self.app:
                self.app.logger.info("Redis listener started, subscribed to 'aml-events' channel")

            def _listen():
                consecutive_errors = 0
                max_consecutive_errors = 5
                if self.app:
                    self.app.logger.info("Redis listener thread started")
                while True:
                    try:
                        # Use get_message with timeout for faster response
                        raw = self._redis_pubsub.get_message(timeout=0.1)
                        if raw and raw.get("type") == "message":
                            try:
                                message = json.loads(raw["data"])
                                if message.get("publisher") == self._instance_id:
                                    if self.app:
                                        self.app.logger.debug(f"Skipping own event from Redis: {message.get('event')}")
                                    continue
                                event_name = message.get("event")
                                # Skip internal SocketIO events to prevent infinite loops
                                if event_name in ['connect', 'disconnect', 'heartbeat']:
                                    if self.app:
                                        self.app.logger.debug(f"Skipping internal SocketIO event from Redis: {event_name}")
                                    continue
                                if self.app:
                                    self.app.logger.info(f"Received event from Redis: {event_name}")
                                self._local_deliver(event_name, message.get("data"))
                                consecutive_errors = 0  # Reset error counter on success
                            except Exception as e:
                                if self.app:
                                    self.app.logger.error(f"Error processing Redis message: {e}")
                                consecutive_errors += 1
                    except Exception as e:
                        consecutive_errors += 1
                        if self.app:
                            self.app.logger.error(f"Redis listener error: {e}")
                        # If too many consecutive errors, wait longer before reconnecting
                        if consecutive_errors >= max_consecutive_errors:
                            if self.app:
                                self.app.logger.warning(f"Too many consecutive Redis errors ({consecutive_errors}), waiting 5 seconds before reconnect")
                            time.sleep(5)
                        else:
                            # Brief pause before reconnecting
                            time.sleep(0.5)
                        try:
                            self._redis_pubsub = self._redis_client.pubsub(ignore_subscribe_messages=True)
                            self._redis_pubsub.subscribe("aml-events")
                        except:
                            pass

            thread = threading.Thread(target=_listen, daemon=True)
            thread.start()
        except Exception as e:
            if self.app:
                self.app.logger.error(f"Failed to start Redis listener: {e}")
            self._redis_pubsub = None

    def _local_deliver(self, event_name, payload):
        """Deliver event locally to subscribers and SocketIO."""
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
        
        # Flask-SocketIO's emit is safe to call from worker/background threads.
        # Starting a new OS thread for every event eventually exhausts resources
        # during sustained transaction activity and makes connected clients appear
        # to stop receiving updates.
        if self.socketio is not None:
            try:
                self.socketio.emit(event_name, payload)
                if self.app:
                    self.app.logger.info(f"SocketIO broadcast event: {event_name}")
            except Exception as e:
                if self.app:
                    self.app.logger.error(f"SocketIO broadcast failed for {event_name}: {e}")

    def set_socketio(self, socketio):
        """Set the SocketIO instance."""
        self.socketio = socketio

    def add_subscriber(self, queue):
        """Add a queue as a subscriber."""
        self._subscribers.append(queue)
        if self.app is not None:
            app_subscribers = self.app.config.setdefault("STREAM_SUBSCRIBERS", [])
            if queue not in app_subscribers:
                app_subscribers.append(queue)
        return queue

    def remove_subscriber(self, queue):
        """Remove a queue from subscribers."""
        if queue in self._subscribers:
            self._subscribers.remove(queue)
        if self.app is not None:
            app_subscribers = self.app.config.get("STREAM_SUBSCRIBERS", [])
            if queue in app_subscribers:
                app_subscribers.remove(queue)

    def publish(self, event_name, payload):
        """Publish an event to all subscribers and external brokers."""
        # Skip publishing internal SocketIO events to Redis to prevent infinite loops
        if event_name in ['connect', 'disconnect', 'heartbeat']:
            if self.app:
                self.app.logger.info(f"Skipping Redis publish for internal event: {event_name}")
            self._local_deliver(event_name, payload)
            return

        message = {"event": event_name, "data": payload, "publisher": self._instance_id}
        if self.app:
            self.app.logger.info(f"RealtimeBroker.publish called for event: {event_name}")
        self._local_deliver(event_name, payload)

        # Publish to Redis in background thread to avoid blocking
        if self._redis_client is not None:
            def publish_to_redis():
                try:
                    self._redis_client.publish("aml-events", json.dumps(message))
                    if self.app:
                        self.app.logger.info(f"Published event to Redis: {event_name}")
                except Exception as e:
                    if self.app:
                        self.app.logger.error(f"Failed to publish event to Redis: {e}")
            threading.Thread(target=publish_to_redis, daemon=True).start()
        else:
            if self.app:
                self.app.logger.warning("Redis client not available, event not published to Redis")

        if self._kafka_producer is not None:
            try:
                self._kafka_producer.send("aml-events", message)
            except Exception:
                pass

    def queue_for_offline_user(self, user_id, event_name, payload):
        """Queue message for offline user to deliver when they reconnect."""
        if self._redis_client is None:
            if self.app:
                self.app.logger.warning("Redis not available, cannot queue offline message")
            return
        
        try:
            offline_queue_key = f"offline_queue:user:{user_id}"
            message = {"event": event_name, "data": payload, "timestamp": int(time.time())}
            self._redis_client.lpush(offline_queue_key, json.dumps(message))
            self._redis_client.ltrim(offline_queue_key, 0, 99)  # Keep last 100 messages
            self._redis_client.expire(offline_queue_key, 86400)  # 24 hour TTL
            if self.app:
                self.app.logger.info(f"Queued event {event_name} for offline user {user_id}")
        except Exception as e:
            if self.app:
                self.app.logger.error(f"Failed to queue offline message for user {user_id}: {e}")

    def get_offline_queue(self, user_id):
        """Retrieve queued messages for user who just reconnected."""
        if self._redis_client is None:
            return []
        
        try:
            offline_queue_key = f"offline_queue:user:{user_id}"
            messages = self._redis_client.lrange(offline_queue_key, 0, -1)
            self._redis_client.delete(offline_queue_key)
            return [json.loads(msg) for msg in messages]
        except Exception as e:
            if self.app:
                self.app.logger.error(f"Failed to retrieve offline queue for user {user_id}: {e}")
            return []

    def stream_response(self):
        """Generate Server-Sent Events response for streaming."""
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
