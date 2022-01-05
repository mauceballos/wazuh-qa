import logging
import os
import random
import socket
import subprocess
import time

LOGGER_NAME = "add_agents.log"


def check_host_master_node():
    proc1 = subprocess.Popen(['/var/ossec/bin/cluster_control', '-l'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'master'], stdin=proc1.stdout,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()

    ip_master = (out.split()[-1]).decode("utf-8")
    return True if ip_master == socket.gethostname().split('.')[0].replace('ip-', '').replace('-', '.') else False


class CustomLogger:
    def __init__(self, name, file_path=f'/tmp/{LOGGER_NAME}', foreground=False, level=logging.INFO):
        logger = logging.getLogger(name)
        logger_formatter = logging.Formatter('{asctime} {levelname}: [{thread_name}] {message}', style='{',
                                             datefmt='%Y/%m/%d %H:%M:%S')
        logging.basicConfig(filename=file_path, filemode='a', level=level,
                            format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y/%m/%d %H:%M:%S')

        if foreground:
            ch = logging.StreamHandler()
            ch.setFormatter(logger_formatter)
            logger.addHandler(ch)

        self.logger = logger

    def get_logger(self):
        return self.logger


def main():
    if check_host_master_node():
        logger = CustomLogger('Add_agents').get_logger()

        agents_list = list(range(1, 100000))
        agents_list = [str(agent_id).zfill(3) for agent_id in agents_list]
        logger.info("Starting add_agents script.")

        while not os.path.exists('/var/ossec/etc/client.keys'):
            logger.info("client.keys does not exist, waiting 15 seconds...")
            time.sleep(15)

        # Add agents to client.keys
        with open(file='/var/ossec/etc/client.keys', mode='a') as f:
            for agent_id in range(0, len(agents_list)):
                f.write(f"{str(agent_id).zfill(3)} new_agent_{agent_id} any {agent_id}\n")
                f.flush()
                if agent_id % 5000 == 0:
                    logger.info(f"The first {agent_id} agents have already been added.")

        # Add agent-groups files
        logger.info("Starting to add agents to groups.")
        for idx, agent_id in enumerate(agents_list):
            agent_group_file = f"/var/ossec/queue/agent-groups/{agent_id}"
            if not os.path.exists(agent_group_file):
                with open(file=agent_group_file, mode='w') as f:
                    f.write('default')
                if idx % 5000 == 0:
                    logger.info(f"The first {agent_id} agents have already been added.")

    exit(0)


if __name__ == "__main__":
    logger = CustomLogger('Add_agents').get_logger()
    try:
        main()
    except Exception as e:
        logger.info(f"Exception raised {e.__dict__}")
