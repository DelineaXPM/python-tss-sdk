"""The Delinea Secret Server Python SDK"""

# 3.0.0, not 2.0.2: this line is the published version (flit reads it), and
# the branch carries four breaking changes -- the attachment ``itemValue``
# type, requires-python >= 3.10, the requests floor, and ``server_type``
# becoming keyword-only. See work item 741117 and SP-001.
__version__ = "3.0.0"
