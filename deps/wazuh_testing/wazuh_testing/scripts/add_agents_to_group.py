import logging
import os
import socket
import subprocess
import time

LOGGER_NAME = "add_agents_to_group.log"


def check_host_master_node():
    proc1 = subprocess.Popen(['/var/ossec/bin/cluster_control', '-l'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'master'], stdin=proc1.stdout,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()

    ip_master = (out.split()[-1]).decode("utf-8")
    return True if ip_master == socket.gethostname().split('.')[0].replace('ip-', '').replace('-', '.') else False


def get_node_name():
    proc1 = subprocess.Popen(['/var/ossec/bin/cluster_control', '-l'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', 'worker'], stdin=proc1.stdout,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    out, err = proc2.communicate()

    out = out.decode("utf-8")

    ips_list = out.split('\n')
    # Save name and IP in ips_list
    ips_list = [(ip.split()[0], ip.split()[-1]) for ip in ips_list]

    host_ip = socket.gethostname().split('.')[0].replace('ip-', '').replace('-', '.')

    for ip in ips_list:
        if ip[1] == host_ip:
            return 'worker1' if 'worker1' in ip[0] \
                else 'worker2' if 'worker2' in ip[0] \
                else 'worker3' if 'worker3' in ip[0] \
                else 'worker4' if 'worker4' in ip[0] \
                else 'worker5' if 'worker5' in ip[0] \
                else 'master'

    return False


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
    if not check_host_master_node():
        logger = CustomLogger('Add_agents').get_logger()

        worker_name = get_node_name()

        agents_range = \
            (1, 1440) if worker_name == 'worker1' else (
                1441, 2880) if worker_name == 'worker2' else (
                2881, 4320) if worker_name == 'worker3' else (
                4321, 5760) if worker_name == 'worker4' else (5761, 7200)

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
