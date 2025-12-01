"""
Locust load test for API Shield.

Run with:
    locust -f locustfile.py --host http://localhost:8000
"""

import json
import random
import string
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner


def random_ip():
    """Generate random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"


def random_user_id():
    """Generate random user ID."""
    return f"user_{''.join(random.choices(string.ascii_lowercase, k=8))}"


def random_path():
    """Generate random API path."""
    resources = ["users", "orders", "products", "customers", "invoices"]
    resource = random.choice(resources)
    resource_id = random.randint(1, 100000)
    return f"/api/{resource}/{resource_id}"


class NormalUser(HttpUser):
    """Simulates normal API usage patterns."""

    weight = 70  # 70% of users are normal
    wait_time = between(1, 3)

    def on_start(self):
        """Initialize user with consistent identity."""
        self.user_id = random_user_id()
        self.client_ip = random_ip()

    @task(10)
    def get_resource(self):
        """Normal GET request."""
        payload = {
            "method": "GET",
            "path": random_path(),
            "client_ip": self.client_ip,
            "user_id": self.user_id,
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            },
            "response_code": 200,
        }
        self.client.post("/analyze", json=payload)

    @task(3)
    def post_resource(self):
        """Normal POST request."""
        payload = {
            "method": "POST",
            "path": random_path(),
            "client_ip": self.client_ip,
            "user_id": self.user_id,
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "content-type": "application/json",
            },
            "response_code": 201,
        }
        self.client.post("/analyze", json=payload)

    @task(1)
    def check_health(self):
        """Health check."""
        self.client.get("/health")


class BOLAAttacker(HttpUser):
    """Simulates BOLA/IDOR attack patterns."""

    weight = 10  # 10% of traffic is BOLA attacks
    wait_time = between(0.1, 0.5)

    def on_start(self):
        self.user_id = random_user_id()
        self.client_ip = random_ip()
        self.current_id = random.randint(1000, 2000)

    @task
    def enumerate_resources(self):
        """Sequential resource enumeration (BOLA attack)."""
        payload = {
            "method": "GET",
            "path": f"/api/users/{self.current_id}",
            "client_ip": self.client_ip,
            "user_id": self.user_id,
            "headers": {
                "user-agent": "python-requests/2.28.0",
            },
            "response_code": 200,
        }
        self.client.post("/analyze", json=payload)
        self.current_id += 1  # Sequential enumeration


class BruteForceAttacker(HttpUser):
    """Simulates brute force authentication attacks."""

    weight = 10  # 10% of traffic is brute force
    wait_time = between(0.1, 0.3)

    def on_start(self):
        self.client_ip = random_ip()
        self.target_user = random_user_id()

    @task
    def failed_login(self):
        """Failed authentication attempt."""
        payload = {
            "method": "POST",
            "path": "/api/auth/login",
            "client_ip": self.client_ip,
            "user_id": self.target_user,
            "headers": {
                "user-agent": "python-requests/2.28.0",
                "content-type": "application/json",
            },
            "response_code": 401,  # Failed auth
        }
        self.client.post("/analyze", json=payload)


class RateLimitAttacker(HttpUser):
    """Simulates rate limit abuse."""

    weight = 10  # 10% of traffic is rate abuse
    wait_time = between(0, 0.05)  # Very fast requests

    def on_start(self):
        self.user_id = random_user_id()
        self.client_ip = random_ip()

    @task
    def flood_requests(self):
        """Rapid request flood."""
        payload = {
            "method": "GET",
            "path": "/api/data",
            "client_ip": self.client_ip,
            "user_id": self.user_id,
            "headers": {
                "user-agent": "curl/7.68.0",
            },
            "response_code": 200,
        }
        self.client.post("/analyze", json=payload)


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    """Initialize event listener."""
    if isinstance(environment.runner, MasterRunner):
        print("Running in distributed mode as master")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Log test start."""
    print("=" * 60)
    print("API Shield Load Test Started")
    print("=" * 60)
    print("User distribution:")
    print("  - Normal users: 70%")
    print("  - BOLA attackers: 10%")
    print("  - Brute force attackers: 10%")
    print("  - Rate limit attackers: 10%")
    print("=" * 60)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Log test results."""
    print("\n" + "=" * 60)
    print("API Shield Load Test Completed")
    print("=" * 60)

    stats = environment.stats
    print(f"Total requests: {stats.total.num_requests}")
    print(f"Failures: {stats.total.num_failures}")
    print(f"Median response time: {stats.total.median_response_time}ms")
    print(f"95th percentile: {stats.total.get_response_time_percentile(0.95)}ms")
    print(f"99th percentile: {stats.total.get_response_time_percentile(0.99)}ms")
    print(f"Requests/sec: {stats.total.current_rps}")
    print("=" * 60)
