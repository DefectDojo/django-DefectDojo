'''
Created on Feb 18, 2015

@author: jay7958
'''
from django.urls import re_path
from django.contrib import admin
from django.apps import apps
from dojo.survey import views
if not apps.ready:
    apps.get_models()

admin.autodiscover()

urlpatterns = [
    re_path(r'^questionnaire$',
        views.questionnaire,
        name='questionnaire'),
    re_path(r'^questionnaire/create$',
        views.create_questionnaire,
        name='create_questionnaire'),
    re_path(r'^questionnaire/(?P<sid>\d+)/edit$',
        views.edit_questionnaire,
        name='edit_questionnaire'),
    re_path(r'^questionnaire/(?P<sid>\d+)/delete',
        views.delete_questionnaire,
        name='delete_questionnaire'),
    re_path(r'^questionnaire/(?P<sid>\d+)/edit/questions$',
        views.edit_questionnaire_questions,
        name='edit_questionnaire_questions'),
    re_path(r'^questions$',
        views.questions,
        name='questions'),
    re_path(r'^questions/add$',
        views.create_question,
        name='create_question'),
    re_path(r'^questions/(?P<qid>\d+)/edit$',
        views.edit_question,
        name='edit_question'),
    re_path(r'^choices/add$',
        views.add_choices,
        name='add_choices'),
    re_path(r'^engagement/(?P<eid>\d+)/add_questionnaire$',
        views.add_questionnaire,
        name='add_questionnaire'),
    re_path(r'^engagement/(?P<eid>\d+)/questionnaire/(?P<sid>\d+)/answer',
        views.answer_questionnaire,
        name='answer_questionnaire'),
    re_path(r'^engagement/(?P<eid>\d+)/questionnaire/(?P<sid>\d+)/delete',
        views.delete_engagement_survey,
        name='delete_engagement_survey'),
    re_path(r'^engagement/(?P<eid>\d+)/questionnaire/(?P<sid>\d+)$',
        views.view_questionnaire,
        name='view_questionnaire'),
    re_path(r'^engagement/(?P<eid>\d+)/questionnaire/(?P<sid>\d+)/assign',
        views.assign_questionnaire,
        name='assign_questionnaire'),

    # Questionnaires without an engagemnet
    re_path(r'^empty_questionnaire$',
        views.add_empty_questionnaire,
        name='add_empty_questionnaire'),
    re_path(r'^empty_questionnaire/(?P<esid>\d+)$',
        views.view_empty_survey,
        name='view_empty_survey'),
    re_path(r'^empty_questionnaire/(?P<esid>\d+)/delete$',
        views.delete_empty_questionnaire,
        name='delete_empty_questionnaire'),
    re_path(r'^general_questionnaire/(?P<esid>\d+)/delete$',
        views.delete_general_questionnaire,
        name='delete_general_questionnaire'),
    re_path(r'^empty_questionnaire/(?P<esid>\d+)/answer$',
        views.answer_empty_survey,
        name='answer_empty_survey'),
    re_path(r'^empty_questionnaire/(?P<esid>\d+)/new_engagement$',
        views.engagement_empty_survey,
        name='engagement_empty_survey'),
]
