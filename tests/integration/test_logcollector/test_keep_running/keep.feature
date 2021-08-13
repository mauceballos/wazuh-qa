Feature: keep-running
  Check if Wazuh works correctly when monitoring log files (through `logcollector`) and these are modified by a log rotation.
  Scenario: logcollector continues to monitor log files after they have been rotated
    Given Get configurations from the module
    And Get internal configuration
    And Get file list to create from the module

    When The file is being analyzed
    And Add another MiB of data to log

    Then Rotation or truncate has been completed
    And Add a MiB of data to rotated/truncated log