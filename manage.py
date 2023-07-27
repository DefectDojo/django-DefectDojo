#!/usr/bin/env python
import os
import sys
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

    resource = Resource(attributes={"service.name": "defectdojo"})
    trace.set_tracer_provider(TracerProvider(resource=resource))
    tracer = trace.get_tracer(__name__)

    otlp_exporter = OTLPSpanExporter(endpoint="http://localhost:4317", insecure=True)

    span_processor = BatchSpanProcessor(otlp_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
