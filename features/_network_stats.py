from collectors.anyrun import AnyRunTask


def get_traffic_size_download(task: AnyRunTask) -> int:
    return task.traffic_recv


def get_traffic_size_upload(task: AnyRunTask) -> int:
    return task.traffic_send


def get_connections_num(task: AnyRunTask) -> int:
    return task.connections_num
