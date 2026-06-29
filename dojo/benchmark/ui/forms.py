from django import forms

from dojo.benchmark.models import (
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
)


class Benchmark_Product_SummaryForm(forms.ModelForm):

    class Meta:
        model = Benchmark_Product_Summary
        exclude = ["product", "current_level", "benchmark_type", "asvs_level_1_benchmark", "asvs_level_1_score", "asvs_level_2_benchmark", "asvs_level_2_score", "asvs_level_3_benchmark", "asvs_level_3_score"]


class DeleteBenchmarkForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Benchmark_Product_Summary
        fields = ["id"]


class BenchmarkForm(forms.ModelForm):

    class Meta:
        model = Benchmark_Product
        exclude = ["product", "control"]


class Benchmark_RequirementForm(forms.ModelForm):

    class Meta:
        model = Benchmark_Requirement
        exclude = [""]
