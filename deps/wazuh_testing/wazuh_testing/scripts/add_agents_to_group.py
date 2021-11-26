import os
import sys
import logging
import time
import socket

LOGGER_NAME = "add_agents_to_group.log"


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
    if socket.gethostname() != 'wazuh-master':
        logger = CustomLogger('Add_agents').get_logger()

        agents_range = \
            (1, 1440) if socket.gethostname() == 'wazuh-worker1' else (
                1441, 2880) if socket.gethostname() == 'wazuh-worker2' else (
                2881, 4320) if socket.gethostname() == 'wazuh-worker3' else (
                4321, 5760) if socket.gethostname() == 'wazuh-worker4' else (5761, 7200)

        first_agent_ID = agents_range[0]
        last_agent_ID = agents_range[1]

        agents_list = [str(agent_id).zfill(3) for agent_id in range(first_agent_ID, last_agent_ID)]

        for _ in range(1, 7200):
            logger.info("Reading client.keys")
            with open(file='/var/ossec/etc/client.keys', mode='r') as f:
                agents_in_client_keys = f.read().split('\n')[:-1]
            agents_in_client_keys = [agent_id.split()[0] for agent_id in agents_in_client_keys]

            logger.info(
                f"Creating agent-groups file for available agents with ID in range {first_agent_ID}-{last_agent_ID}")
            for agent_id in set(agents_list).intersection(set(agents_in_client_keys)):
                agent_group_file = f"/var/ossec/queue/agent-groups/{agent_id}"
                if not os.path.exists(agent_group_file):
                    with open(file=agent_group_file, mode='w') as f:
                        f.write('default')

            time.sleep(60)
    exit(0)


if __name__ == '__main__':
    main()
