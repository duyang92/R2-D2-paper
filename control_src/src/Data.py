import json

class JsonRead:
    json_obj = ''

    def __init__(
            self,
            file_addr,
            read_mod
    ):
        self.file_addr = file_addr
        self.read_mod = read_mod
        f = open(file_addr, read_mod)
        self.json_obj = json.load(f)
        f.close()


def get_payload(attack_name):
    json_obj = JsonRead("../task_interface/payload.json", "r").json_obj
    # print(json_obj)
    return dict(json_obj[attack_name])

if __name__ == "__main__":
    get_payload()
    pass
