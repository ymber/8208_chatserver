import time
import numpy as np

class BotDetection:
    def _init_(self):
        self.request_logs = {}
        self.captcha_question = ""
        self.captcha_answer = 0

    def log_request(self, ip_address):
        """Log each request made by an IP address along with the timestamp."""
        if ip_address not in self.request_logs:
            self.request_logs[ip_address] = []
        self.request_logs[ip_address].append(time.time())

    def check_request_rate(self, ip_address, max_requests=10, period=60):
        """Check if an IP address has made too many requests in a given period.
        
        Args:
            ip_address (str): The IP address to check.
            max_requests (int): The maximum number of requests allowed in the period.
            period (int): The period of time (in seconds) to look back for requests.
        
        Returns:
            bool: True if the request rate is too high, False otherwise.
        """
        now = time.time()
        if ip_address in self.request_logs:
            recent_requests = [req for req in self.request_logs[ip_address] if now - req <= period]
            return len(recent_requests) > max_requests
        return False

    def generate_captcha(self):
        """Generate a simple math CAPTCHA question and answer."""
        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)
        self.captcha_question = f"{num1} + {num2} = ?"
        self.captcha_answer = num1 + num2
        return self.captcha_question

    def verify_captcha(self, answer):
        """Verify the provided answer against the CAPTCHA's answer."""
        return answer == self.captcha_answer

    def check_for_regular_intervals(self, ip_address, tolerance=0.5):
        """Check if requests from an IP address come at regular intervals.
        
        Args:
            ip_address (str): The IP address to check.
            tolerance (float): The allowed variance in seconds between requests to consider them regular.
        
        Returns:
            bool: True if the request intervals are regular within the given tolerance, False otherwise.
        """
        timestamps = self.request_logs.get(ip_address, [])
        if len(timestamps) < 3:  # Need at least 3 points to check for regularity
            return False

        # Calculate the differences between consecutive timestamps
        intervals = np.diff(sorted(timestamps))

        # Calculate the mean interval and check if all intervals are within the tolerance of this mean
        mean_interval = np.mean(intervals)
        return np.all(np.abs(intervals - mean_interval) <= tolerance)

# Example usage
detector = BotDetection()
ip_address = "127.0.0.1"

# Log requests from an IP at regular intervals
for _ in range(10):
    detector.log_request(ip_address)
    # Simulate a request interval between 0.5 and 1.5 seconds
    time.sleep(np.random.uniform(0.1, 2))

# Check for regular intervals
if detector.check_for_regular_intervals(ip_address):
    print("Detected regular request intervals. This might be a bot.")
else:
    print("Request intervals are irregular. Likely not a bot.")