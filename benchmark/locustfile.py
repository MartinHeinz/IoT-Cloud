import urllib3
from locust import HttpLocust, TaskSet, task, TaskSequence, seq_task

DEVICE_ID = 23
DEVICE_NAME_BI = 'a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df'
ACTION_NAME_BI = '86a638eab77f45b9e0e2fb384471e517664df67cec75c33d724efa8649be357e'
SCENE_NAME_BI = '0b0a367318926df75879294f1520905ba72d8f1bebe64865645a7e108bfaf3e4'
ACCESS_TOKEN_USER_1 = "5c36ab84439c45a3719644c0d9bd7b31929afd9f"
ACCESS_TOKEN_USER_2 = "5c36ab84439c55a3c196f4csd9bd7b319291239f"
AA_ACCESS_TOKEN_USER_1 = '54agPr4edV9PvyyBNkjFfA))'
AA_ACCESS_TOKEN_USER_2 = '7jagPr4edVdgvyyBNkjdaQ))'
PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDM0W/Tn8gv7VjDzvGMqke8rcfZe2zWAG\nRdABvWRRZNmioOeH8U/gFBgiDd9Nd61JuTa3BQx' \
                 'WUYPEMNsSF3yWjlWlzgJCxwJX\nE80D4mcE/gNLI3+86bs4q3wWcJY0fk3I\n-----END PUBLIC KEY-----\n'


class AttrAuthUserBehavior(TaskSet):

    @task()
    def key_setup(self):
        data = {"access_token": AA_ACCESS_TOKEN_USER_1}
        with self.client.get("/attr_auth/setup",
                             name="/attr_auth/setup",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def keygen(self):
        data = {
            "attr_list": "2 2-1 2-GUEST",
            "receiver_id": "1",
            "device_id": "1",
        }
        with self.client.post("/attr_auth/user/keygen",
                              name="/attr_auth/user/keygen",
                              params={"access_token": AA_ACCESS_TOKEN_USER_2},
                              data=data,
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
        with self.client.get("/attr_auth/encrypt",
                             name="/attr_auth/encrypt",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                self.ciphertext = response.json()["ciphertext"]
                response.success()
            else:
                print(response.json())

    @seq_task(2)
    def decrypt(self):
        data = {
            "access_token": AA_ACCESS_TOKEN_USER_2,
            "api_username": "MartinHeinz",
            "ciphertext": self.ciphertext
        }
        with self.client.get("/attr_auth/decrypt",
                             name="/attr_auth/decrypt",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                print(response.json())


class UserBehavior(TaskSet):

    @task()
    def get_device_data(self):
        data = {"device_name_bi": DEVICE_NAME_BI, "access_token": ACCESS_TOKEN_USER_1}
        with self.client.get("/api/data/get_device_data",
                             name="/api/data/get_device_data",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def get_device_by_name(self):
        data = {"name_bi": DEVICE_NAME_BI, "access_token": ACCESS_TOKEN_USER_1}
        with self.client.get("/api/device/get",
                             name="/api/device/get",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def create_device(self):
        data = {
            "type_id": "12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5",
            "correctness_hash": '$2b$12$WCDgDQQwfA2UtS7qk5eiO.W23sRkaHjKSBWrkhB8Q9VGPUnMUKtye',
            "name": "test",
            "password": 'PBKDF2$sha256$10000$9tPL2IDSekCbDADg$McfGrlUVABIVQ8mlwBMPtrLH5BemxT5A',
            "name_bi": "$2b$12$1xxxxxxxxxxxxxxxxxxxxuDUX01AKuyu/3/PdSxQT4qMDVTUawIUq"
        }
        with self.client.post("/api/device/create",
                              name="/api/device/create",
                              params={"access_token": ACCESS_TOKEN_USER_1},
                              data=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def get_data_by_num_range(self):
        data = {
            "lower": "467297",
            "access_token": ACCESS_TOKEN_USER_1,
            "device_name_bi": DEVICE_NAME_BI}  # OPE - 2500
        with self.client.get("/api/data/get_by_num_range",
                             name="/api/data/get_by_num_range",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def trigger_action(self):
        data = {
            "device_id": DEVICE_ID,
            "name_bi": ACTION_NAME_BI,
            "access_token": ACCESS_TOKEN_USER_1,
            "additional_data": 'gAAAAABcikpQSsh7iACV6pAFMaldncaSrA9rj3iUh-7ejFnvXw1Uzcodf5Gf7FtZTU39R3L65nd1RzExvF9kMU1t_YwG2FpdMA=='
        }
        with self.client.get("/api/device/action",
                             name="/api/device/action",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def trigger_scene(self):
        data = {
            "name_bi": SCENE_NAME_BI,
            "access_token": ACCESS_TOKEN_USER_2,
        }
        with self.client.get("/api/scene/trigger",
                             name="/api/scene/trigger",
                             params=data,
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def exchange_session_keys(self):
        data = {
            "public_key": PUBLIC_KEY,
            "device_id": 34
        }
        with self.client.post("/api/exchange_session_keys",
                              name="/api/exchange_session_keys",
                              params={"access_token": ACCESS_TOKEN_USER_2},
                              data=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()


class WebsiteUser(HttpLocust):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    task_set = UserBehavior  # Or AttrAuthUserBehavior or AttrAuthUserEncryptAndDecrypt
    min_wait = 2000
    max_wait = 5000

    # Run using: locust --host=https://localhost
