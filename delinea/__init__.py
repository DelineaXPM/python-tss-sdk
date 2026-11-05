"""The Delinea Secret Server Python SDK"""

# 3.0.0, not 2.0.2: this line is the published version (flit reads it), and
# the branch carries five breaking changes -- the attachment ``itemValue``
# type, requires-python >= 3.10, the requests floor, ``server_type`` becoming
# keyword-only, and a non-https ``base_url`` now raising instead of warning
# (opt out with ``allow_http=True``). See work item 741117.
__version__ = "3.0.0"
