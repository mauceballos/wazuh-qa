import datetime
from time import time

from wazuh_testing.db_interface import query_wdb


def clean_table(agent_id, table):
    """Delete all table entries of the agent DB using wazuh_db.

    Args:
        agent_id (str): Agent ID.
        table (str): table from the agent DB.
    """
    query_string = f"agent {agent_id} sql DELETE FROM {table}"
    query_wdb(query_string)


def update_last_full_scan(last_scan=0, agent_id='000'):
    """Update the last scan of an agent.

    Args:
        last_scan (int): Last scan ID. This is compute by casting to int the result of time()
        agent_id (str): Agent ID
    """
    query_string = f"agent {agent_id} sql UPDATE vuln_metadata SET LAST_FULL_SCAN={last_scan}"
    query_wdb(query_string)


def insert_hotfix(agent_id='000', scan_id=int(time()), scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                  hotfix='000000', checksum='dummychecksum'):
    """Insert a hotfix.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Last scan ID.
        scan_time (str): Scan date ("%Y/%m/%d %H:%M:%S")
        hotfix (str): ID of the hotfix value.
        checksum (str): Hotfix checksum
    """
    query_string = f"agent {agent_id} sql INSERT INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES " \
                   f"({scan_id}, '{scan_time}', '{hotfix}', '{checksum}')"
    query_wdb(query_string)


def insert_os_info(agent_id='000', scan_id=int(time()), scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                   hostname='centos8', architecture='x86_64', os_name='CentOS Linux', os_version='8.4', os_major='8',
                   os_minor='4', os_build='', version='', os_release='', os_patch='', release='',
                   checksum='dummychecksum'):
    """Insert the OS information in the agent database.

    Args:
        agent_id (str): id of the agent
        scan_id (int): id of the last scan
        scan_time (str): date of the scan with this format "%Y/%m/%d %H:%M:%S"
        hostname (str): name of the host
        architecture (str): architecture of the host
        os_name (str): complete name of the OS
        os_version (str): version of the OS
        os_major (str): major version of the OS
        os_minor (str): minor version of the OS
        os_build (str): build id of the OS
        version (str): version of the OS
        os_release (str): release of the OS
        os_patch (str): current patch of the OS
        release (str): release of the OS
        checksum (str): checksum of the OS
    """
    query_string = f"agent {agent_id} sql INSERT OR REPLACE INTO sys_osinfo (scan_id, scan_time, hostname, " \
                   'architecture, os_name, os_version, os_major, os_minor, os_patch, os_build, release, version, ' \
                   f"os_release, checksum) VALUES ('{scan_id}', '{scan_time}', '{hostname}', '{architecture}', " \
                   f"'{os_name}', '{os_version}', '{os_major}', '{os_minor}', '{os_patch}', '{os_build}', " \
                   f"'{release}', '{version}', '{os_release}', '{checksum}')"
    query_wdb(query_string)


def insert_package(agent_id='000', scan_id=int(time()), format='rpm', name=vd.DEFAULT_PACKAGE_NAME,
                   priority='', section='Unspecified', size=99, vendor='wazuhintegrationtests', version='1.0.0-1.el7',
                   architecture='x86_64', multiarch='', description='Wazuh Integration tests mock package',
                   source='Wazuh Integration tests mock package', location='', triaged=0,
                   install_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                   scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"), checksum='dummychecksum',
                   item_id='dummyitemid'):
    """Insert a package in the agent DB

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Last scan ID.
        format (str): Package format (deb, rpm, ...)
        name (str): Package name
        priority (str): Released package priority.
        section (str): Package section.
        size (int): Package size.
        vendor (str): Package vendor.
        version (str): Package version.
        architecture (str): Package architecture.
        multiarch (str): Define if a package may be installed in different architectures.
        description (str): Package description.
        source (str): Package source.
        location (str): Package location
        triaged (int): Times that the package has been installed.
        install_time (str): Installation timestamp
        scan_time (str): Scan timestamp
        checksum (str): Package checksum.
        item_id (str): Package ID.
    """
    arguments = locals()
    for key, value in arguments.items():
        if type(value) is str:
            if value != 'NULL':
                arguments[key] = f"'{value}'"

    query_wdb(f"agent {agent_id} sql INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, "
              f"size, vendor, install_time, version, architecture, multiarch, source, description, location, triaged,"
              f"checksum, item_id) VALUES ({arguments['scan_id']}, {arguments['scan_time']}, {arguments['format']},"
              f"{arguments['name']}, {arguments['priority']}, {arguments['section']}, {arguments['size']},"
              f"{arguments['vendor']}, {arguments['install_time']}, {arguments['version']},"
              f"{arguments['architecture']}, {arguments['multiarch']}, {arguments['source']}, "
              f"{arguments['description']}, {arguments['location']}, {arguments['triaged']}, {arguments['checksum']},"
              f"{arguments['item_id']})")


def update_sync_info(agent_id='000', component='syscollector-packages', last_attempt=1, last_completion=1,
                     n_attempts=0, n_completions=0, last_agent_checksum=''):
    """Update the sync_info table of the specified agent for the selected component."""
    query_wdb(f"agent {agent_id} sql UPDATE sync_info SET last_attempt = {last_attempt},"
              f"last_completion = {last_completion}, n_attempts = {n_attempts}, n_completions = {n_completions},"
              f"last_agent_checksum = '{last_agent_checksum}' where component = '{component}'")


def update_package(version, package, agent_id='000'):
    """Update version of installed package in database.

    Used to simulate upgrades and downgrades of the package given.

    Args:
        version (str): Package version.
        package (str): Package name.
        agent_id (str): Agent ID.
    """
    update_query_string = f'agent {agent_id} sql UPDATE sys_programs SET version="{version}" WHERE name="{package}"'
    query_wdb(update_query_string)


def delete_package(package, agent_id='000'):
    """Remove package from database.

    Used to simulate uninstall of the package given.

    Args:
        package (str): Package name
        agent_id (str): agent ID.
    """
    delete_query_string = f'agent {agent_id} sql DELETE FROM sys_programs WHERE name="{package}"'
    query_wdb(delete_query_string)


def clean_vulnerabilities_inventory(agent_id='000'):
    """Clean the vulnerabilities inventory from database.

    Args:
        agent_id (str): Agent ID.
    """
    clean_query_string = f"agent {agent_id} sql DELETE from vuln_cves"
    query_wdb(clean_query_string)


def modify_agent_scan_timestamp(agent_id='000', timestamp=0, full_scan=True):
    """Update the timestamp of the agent scans in the vuln_metadata table.

    Args:
        agent_id (str): Agent ID.
        timestamp (int): Timestamp value to set.
        full_scan (bool): True for set LAST_FULL_SCAN or False to set LAST_SCAN.
    """
    scan_type = "LAST_FULL_SCAN" if full_scan else "LAST_PARTIAL_SCAN"
    query_wdb(f"agent {agent_id} sql UPDATE vuln_metadata SET {scan_type}={timestamp}")


def delete_os_info_data(agent_id='000'):
    """Delete the sys_osinfo data from a specific agent

    Args:
        agent_id (str): Agent ID.
    """
    query_wdb(f"agent {agent_id} sql DELETE FROM sys_osinfo")
