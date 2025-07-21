import logging
import traceback


class SQLTraceFilter(logging.Filter):
    def filter(self, record):
        import traceback
        stack = traceback.extract_stack()
        for frame in reversed(stack):
            if "dojo" in frame.filename and "dojo/logfilters.py" not in frame.filename:
                record.origin = f"{frame.filename}:{frame.lineno}"
                break
        else:
            record.origin = "unknown"
        return True
