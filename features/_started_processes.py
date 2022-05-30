from collectors.anyrun import AnyRunTask


def get_started_processes_num(task: AnyRunTask) -> int:
    return len(task.processes)
