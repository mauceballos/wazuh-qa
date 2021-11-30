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

        agents_list = list(range(1, 7200))
        agents_list = [str(agent_id).zfill(3) for agent_id in agents_list]
        logger.info("Starting add_agents script, shuffling agents ID list with range [001-7200]")
        random.shuffle(agents_list)

        logger.info(f"Agents with ID {', '.join(agents_list[:5])}, ... are going to be added to the client.keys file")

        while not os.path.exists('/var/ossec/etc/client.keys'):
            logger.info("client.keys does not exist, waiting 15 seconds...")
            time.sleep(15)
        for chunk in [agents_list[x:x + 50] for x in range(0, len(agents_list), 50)]:
            f = open(file='/var/ossec/etc/client.keys', mode='a')
            logger.info(f"Adding 50 agents with IDs: {', '.join(chunk[:5])}, ...")
            for agent_id in chunk:
                f.write(f"{str(agent_id).zfill(3)} new_agent_{agent_id} any {agent_id}\n")
                f.flush()  # This is important to avoid bytes staying in the buffer until the loop has finished
            f.close()
            logger.info("Sleeping for 60 seconds ...")
            time.sleep(60)
    exit(0)


if __name__ == "__main__":
    logger = CustomLogger('Add_agents').get_logger()
    try:
        main()
    except Exception as e:
        logger.info(f"Exception raised {e.__dict__}")
