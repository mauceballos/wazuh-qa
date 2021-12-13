import socket
import time
from configobj import ConfigObj
import sys
from wazuh_testing.tools import ANALYSIS_STATISTICS_FILE
from wazuh_testing.tools import ANALYSISD_QUEUE_SOCKET_PATH
from threading import Thread

msg = '0912:tmpdir:Dec  2 16:05:37 localhost su[6625]: pam_unix(su:session): session opened for user root by vagrant(uid=0)'


class Injector():
    '''
    This class inject events per second to analysisd and detects dropping events
    '''
    def __init__(self, eps, execution_time):
        self.eps = eps
        self.quantity_of_threads = (eps + 1000 - 1) // 1000
        self.events_per_thread = self.eps // self.quantity_of_threads
        self.total_events_decoded = []
        self.total_events_dropped = []
        self.execution_time = float(execution_time)

    def detect_events_decoded(self, time_limit):
        while True:
            cfg = ConfigObj(ANALYSIS_STATISTICS_FILE)
            total_events_decoded = int(cfg['total_events_decoded'])
            events_dropped = int(cfg['events_dropped'])
            if total_events_decoded > 0:
                self.total_events_decoded.append(total_events_decoded)
            if events_dropped > 0:
                self.total_events_dropped.append(events_dropped)
            if events_dropped > 1000:
                return True
            time_limit -= 1
            time.sleep(1)
            if time_limit <= 0:
                return False

    def send_message(self, message, wazuh_socket):
        for i in range(0, self.events_per_thread):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(wazuh_socket)
            sock.send(message.encode())
            sock.close()

    def start_injector(self):
        actual_execution_time = 0.0
        while actual_execution_time < self.execution_time:
            start = time.perf_counter()

            threads = []
            # Add the 'detector' thread
            threads.append(Thread(target=self.detect_events_decoded, kwargs={'time_limit': self.execution_time}))

            for i in range(0, self.quantity_of_threads): # Add the 'sender' threads
                threads.append(Thread(target=self.send_message, args=(msg, ANALYSISD_QUEUE_SOCKET_PATH)))

            for i, thread in enumerate(threads):
                thread.start()

            for thread in threads:
                thread.join()

            finish = time.perf_counter()
            actual_execution_time += round(finish - start, 2)

        return self.total_events_decoded, self.total_events_dropped
