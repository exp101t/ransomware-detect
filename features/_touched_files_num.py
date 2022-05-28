from collectors.anyrun import AnyRunTask


def get_file_modification_rate(task: AnyRunTask) -> float:
    return task.touched_files_num / task.execution_time
