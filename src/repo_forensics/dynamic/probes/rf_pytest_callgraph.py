"""pytest plugin: collect the runtime call graph for the whole test session."""

import os

import rf_monitor


def pytest_configure(config):
    rf_monitor.start()


def pytest_unconfigure(config):
    rf_monitor.stop_and_dump(os.environ.get("RF_CALLGRAPH_OUT", "rf_callgraph.json"))
