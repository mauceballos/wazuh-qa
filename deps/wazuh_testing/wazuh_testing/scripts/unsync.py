#!/var/ossec/framework/python/bin/python3
# Send msg to WDB

import copy
import logging
import socket
import struct
import subprocess
import sys
import time

LOGGER_NAME = "unsync.log"


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
    ips_list_copy = copy.deepcopy(ips_list)
    ips_list = [(ip.split()[0], ip.split()[-1]) for ip in ips_list_copy[:-1]]

    host_ip = socket.gethostname().split('.')[0].replace('ip-', '').replace('-', '.')

    for ip in ips_list:
        if ip[1] == host_ip:
            return ip[0]

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
        def send_msg(msg):
            msg = struct.pack('<I', len(msg)) + msg.encode()

            # Send msg
            sock.send(msg)

            # Receive response
            data = sock.recv(4)
            data_size = struct.unpack('<I', data[0:4])[0]
            data = sock.recv(data_size).decode(encoding='utf-8', errors='ignore').split(" ", 1)

            return data

        logger = CustomLogger('Unsync').get_logger()
        ADDR = '/var/ossec/queue/db/wdb'

        manager_name = sys.argv[1]

        if manager_name in get_node_name():

            range_id = (1, 72000) if manager_name == 'manager_1' else (72000, 144000) if manager_name == 'manager_2' else \
                (144000, 216000) if manager_name == 'manager_3' else (216000, 288000) if manager_name == 'manager_4' else (
                288000, 360000)

            first_id = range_id[0]
            last_id = range_id[1]

            node_name = get_node_name()

            counter = 0
            while True:
                if counter % 60 == 0:
                    while True:
                        try:
                            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            sock.connect(ADDR)
                            msg = f'global sql UPDATE agent SET node_name = "{node_name}", version="Wazuh v4.0.0" ' \
                                  f'where id>{first_id} and id<={last_id}'
                            logger.info(f"Updating node_name ({node_name}) and version of the agents: {send_msg(msg)}")
                            sock.close()
                            break
                        except Exception as e:
                            logger.error(f"Could not find wdb socket: {e}. Retrying in 10 seconds...")
                            counter += 10
                            time.sleep(10)
                try:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(ADDR)
                    msg = f'global sql UPDATE agent SET sync_status="syncreq", last_keepalive="{int(time.time())}", ' \
                          f'connection_status="active" where id>{first_id} and id<={last_id}'
                    logger.info(f"Updating sync_status of agents between {first_id} and {last_id}: {send_msg(msg)}")
                    sock.close()
                    counter += 10
                    time.sleep(10)
                except KeyboardInterrupt:
                    logger.info("Closing socket")
                    sock.close()
                    exit(0)
                except Exception as e:
                    logger.error(f"An exception was raised: {e}")
                    counter += 10
                    time.sleep(10)
    exit(0)


if __name__ == '__main__':
    logger = CustomLogger('Add_agents').get_logger()
    try:
        main()
    except Exception as e:
        logger.info(f"Exception raised {e.__dict__}")
