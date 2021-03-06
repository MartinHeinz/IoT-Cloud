import random
import string

import urllib3
from locust import HttpLocust, TaskSet, task, TaskSequence, seq_task

DEVICE_ID = 10023
DEVICE_NAME_BI = 'a36758aa531feb3ef0ce632b7a5b993af3d8d59b8f2f8df8de854dce915d20df'
ACTION_NAME_BI = '86a638eab77f45b9e0e2fb384471e517664df67cec75c33d724efa8649be357e'
SCENE_NAME_BI = '0b0a367318926df75879294f1520905ba72d8f1bebe64865645a7e108bfaf3e4'
ACCESS_TOKEN_USER_1 = 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTAwMjk2MCwiZXhwIjo0NzEwNzYyOTYwfQ.eyJpZCI6MTAwMDEsInRva2VuIjoiNWMzNmFiODQ0MzljNDVhMzcxOTY0NGMwZDliZDdiMzE5MjlhZmQ5ZiJ9.StEFlR7-r66-Zpe4KTpRdAZDqNIKpIAKYzY8V_LLA-tNM24xIKSyV2plhwHZtrtIrrkRxkebmkUO1bjLPDhIWw'  # s.dumps({'id': 10001, 'token': "5c36ab84439c45a3719644c0d9bd7b31929afd9f"}).decode(); bcrypt.using(rounds=13).hash('5c36ab84439c45a3719644c0d9bd7b31929afd9f')
ACCESS_TOKEN_USER_2 = 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTAwMjk5OSwiZXhwIjo0NzEwNzYyOTk5fQ.eyJpZCI6MTAwMDIsInRva2VuIjoiNWMzNmFiODQ0MzljNTVhM2MxOTZmNGNzZDliZDdiMzE5MjkxMjM5ZiJ9.mIJVxn4auzTaMoG3im4uzrhPM6_4r5CC-MaNNaw5PVxI9pfrvFFry4OEES4BD6fzCS-oEifyLWM1vhKRUCJ0Bg'  # s.dumps({'id': 10002, 'token': "5c36ab84439c55a3c196f4csd9bd7b319291239f"}).decode(); bcrypt.using(rounds=13).hash('5c36ab84439c55a3c196f4csd9bd7b319291239f')
AA_ACCESS_TOKEN_USER_1 = 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTAwMzA2MywiZXhwIjo0NzEwNzYzMDYzfQ.eyJpZCI6MTAxLCJ0b2tlbiI6IjU0YWdQcjRlZFY5UHZ5eUJOa2pGZkEpKSJ9.MDPW2JGgPuctvxETd1HH00aM1nAkOqtBnYMbolsKXKmfN3aqtan45FvldUAEAxBQ7ept8FydzKaWzGNRFTTDog'  # s.dumps({'id': 101, 'token': '54agPr4edV9PvyyBNkjFfA))'}).decode(); bcrypt.using(rounds=13).hash('54agPr4edV9PvyyBNkjFfA))')
AA_ACCESS_TOKEN_USER_2 = 'eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTAwMzExOSwiZXhwIjo0NzEwNzYzMTE5fQ.eyJpZCI6MTAyLCJ0b2tlbiI6IjdqYWdQcjRlZFZkZ3Z5eUJOa2pkYVEpKSJ9.Y1Q74UwxxPDSLL4jaxDzQytZXcUhf9WnPY0XrH9W7TeT7w48THXWyzBzwS7MeoIJNlmN9cpJOOtcVglHETGAOg'  # s.dumps({'id': 102, 'token': '7jagPr4edVdgvyyBNkjdaQ))'}).decode(); bcrypt.using(rounds=13).hash('7jagPr4edVdgvyyBNkjdaQ))')
PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDM0W/Tn8gv7VjDzvGMqke8rcfZe2zWAG\nRdABvWRRZNmioOeH8U/gFBgiDd9Nd61JuTa3BQx' \
                 'WUYPEMNsSF3yWjlWlzgJCxwJX\nE80D4mcE/gNLI3+86bs4q3wWcJY0fk3I\n-----END PUBLIC KEY-----\n'


class AttrAuthUserBehavior(TaskSet):

    @task()
    def key_setup(self):
        with self.client.get("/attr_auth/setup",
                             name="/attr_auth/setup",
                             headers={"Authorization": AA_ACCESS_TOKEN_USER_1},
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def keygen(self):
        data = {
            "attr_list": "2 2-1 2-GUEST",
            "api_username": "MartinHeinz",
            "device_id": "1",
        }
        with self.client.post("/attr_auth/user/keygen",
                              name="/attr_auth/user/keygen",
                              headers={"Authorization": AA_ACCESS_TOKEN_USER_2},
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
            "message": "any text",
            "policy_string": "(GUESTTODAY)"
        }
        with self.client.get("/attr_auth/encrypt",
                             name="/attr_auth/encrypt",
                             params=data,
                             headers={"Authorization": AA_ACCESS_TOKEN_USER_1},
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
            "api_username": "MartinHeinz",
            "ciphertext": self.ciphertext
        }
        with self.client.get("/attr_auth/decrypt",
                             name="/attr_auth/decrypt",
                             params=data,
                             headers={"Authorization": AA_ACCESS_TOKEN_USER_2},
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                print(response.json())


class MQTTUserBehavior(TaskSet):

    @task()
    def trigger_action(self):
        data = {
            "device_name_bi": DEVICE_NAME_BI,
            "name_bi": ACTION_NAME_BI,
            "additional_data": 'gAAAAABcikpQSsh7iACV6pAFMaldncaSrA9rj3iUh-7ejFnvXw1Uzcodf5Gf7FtZTU39R3L65nd1RzExvF9kMU1t_YwG2FpdMA=='
        }
        with self.client.get("/api/device/action",
                             name="/api/device/action",
                             params=data,
                             headers={"Authorization": ACCESS_TOKEN_USER_1},
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def trigger_scene(self):
        data = {
            "name_bi": SCENE_NAME_BI,
            "additional_data": 'gAAAAABcikpQSsh7iACV6pAFMaldncaSrA9rj3iUh-7ejFnvXw1Uzcodf5Gf7FtZTU39R3L65nd1RzExvF9kMU1t_YwG2FpdMA==',
        }
        with self.client.get("/api/scene/trigger",
                             name="/api/scene/trigger",
                             params=data,
                             headers={"Authorization": ACCESS_TOKEN_USER_2},
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()


class UserBehavior(TaskSet):

    @task()
    def get_device_data(self):
        data = {"device_name_bi": DEVICE_NAME_BI}
        with self.client.get("/api/data/get_device_data",
                             name="/api/data/get_device_data",
                             params=data,
                             headers={"Authorization": ACCESS_TOKEN_USER_1},
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def get_device_by_name(self):
        data = {"name_bi": DEVICE_NAME_BI}
        with self.client.get("/api/device/get",
                             name="/api/device/get",
                             params=data,
                             headers={"Authorization": ACCESS_TOKEN_USER_1},
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def create_device(self):
        data = {
            "type_id": "12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5",
            "correctness_hash": '$2b$12$' + ''.join(random.choice(string.ascii_lowercase) for _ in range(50)),
            "name": "dummy",
            "password": 'PBKDF2$sha256$10000$9tPL2IDSekCbDADg$McfGrlUVABIVQ8mlwBMPtrLH5BemxT5A',
            "name_bi": ''.join(random.choice(string.ascii_lowercase) for _ in range(20))
        }
        with self.client.post("/api/device/create",
                              name="/api/device/create",
                              data=data,
                              headers={"Authorization": ACCESS_TOKEN_USER_1},
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def get_data_by_num_range(self):
        data = {
            "lower": "467297",
            "device_name_bi": DEVICE_NAME_BI}  # OPE - 2500
        with self.client.get("/api/data/get_by_num_range",
                             name="/api/data/get_by_num_range",
                             params=data,
                             headers={"Authorization": ACCESS_TOKEN_USER_1},
                             verify=False,
                             catch_response=True) as response:
            if response.status_code == 200:
                response.success()

    @task()
    def exchange_session_keys(self):
        data = {
            "public_key": PUBLIC_KEY,
            "device_id": 10034
        }
        with self.client.post("/api/exchange_session_keys",
                              name="/api/exchange_session_keys",
                              headers={"Authorization": ACCESS_TOKEN_USER_2},
                              data=data,
                              verify=False,
                              catch_response=True) as response:
            if response.status_code == 200:
                response.success()


class WebsiteUser(HttpLocust):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    task_set = UserBehavior  # Or MQTTUserBehavior or AttrAuthUserBehavior or AttrAuthUserEncryptAndDecrypt
    min_wait = 2000
    max_wait = 5000

    # Run using: locust --host=https://localhost
