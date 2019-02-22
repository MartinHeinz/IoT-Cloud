from locust import HttpLocust, TaskSet, task, TaskSequence, seq_task

DEVICE_ID = 23
DEVICE_NAME_BI = 'a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df'
ACCESS_TOKEN = "5c36ab84439c45a3719644c0d9bd7b31929afd9f"
AA_ACCESS_TOKEN_USER_1 = '54agPr4edV9PvyyBNkjFfA))'
AA_ACCESS_TOKEN_USER_2 = '7jagPr4edVdgvyyBNkjdaQ))'


class AttrAuthUserBehavior(TaskSet):

    @task()
    def key_setup(self):
        data = {"access_token": AA_ACCESS_TOKEN_USER_1}
        with self.client.post("/attr_auth/setup",
                              name="/attr_auth/setup",
                              params=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def keygen(self):
        data = {
            "access_token": AA_ACCESS_TOKEN_USER_2,
            "attr_list": "TODAY GUEST",
            "receiver_id": "1"
        }
        with self.client.post("/attr_auth/keygen",
                              name="/attr_auth/keygen",
                              params=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()


class AttrAuthUserEncryptAndDecrypt(TaskSequence):
    ciphertext = None

    @seq_task(1)
    def encrypt(self):
        data = {
            "access_token": AA_ACCESS_TOKEN_USER_1,
            "message": "any text",
            "policy_string": "(GUESTTODAY)"
        }
        with self.client.post("/attr_auth/encrypt",
                              name="/attr_auth/encrypt",
                              params=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                self.ciphertext = response.json()["ciphertext"]
                response.success()

    @seq_task(2)
    def decrypt(self):
        data = {
            "access_token": AA_ACCESS_TOKEN_USER_2,
            "api_username": "MartinHeinz",
            "ciphertext": self.ciphertext
        }
        with self.client.post("/attr_auth/decrypt",
                              name="/attr_auth/decrypt",
                              params=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()


class UserBehavior(TaskSet):

    @task()
    def get_device_data(self):
        data = {"device_id": DEVICE_ID, "access_token": ACCESS_TOKEN}
        with self.client.post("/api/data/get_device_data",
                              name="/api/data/get_device_data",
                              params=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def get_device_by_name(self):
        data = {"name_bi": DEVICE_NAME_BI, "access_token": ACCESS_TOKEN}
        with self.client.post("/api/device/get",
                              name="/api/device/get",
                              params=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    def create_device(self):
        raise NotImplementedError

    @task()
    def get_data_by_num_range(self):
        data = {"lower": "467297", "access_token": ACCESS_TOKEN, "device_id": DEVICE_ID}  # OPE - 2500
        with self.client.post("/api/data/get_by_num_range",
                              name="/api/data/get_by_num_range",
                              params=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    def trigger_action(self):
        raise NotImplementedError

    def trigger_scene(self):
        raise NotImplementedError

    def exchange_session_keys(self):
        raise NotImplementedError


class WebsiteUser(HttpLocust):
    task_set = UserBehavior  # Or AttrAuthUserBehavior or AttrAuthUserEncryptAndDecrypt
    min_wait = 2000
    max_wait = 5000

    # Run using: locust --host=https://localhost
