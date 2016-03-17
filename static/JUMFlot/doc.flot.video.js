/*
 * The MIT License

Copyright (c) 2010, 2011, 2012, 2013 by Juergen Marsch

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

$.plot.JUMExample.docu.video = {
"docu":"Documentation","video":{
"docu":"video plugin to create videos based on charts.<br>If you want to create your own video, take a closer look to deferred object in jQuery.","data":{
"docu":"There is no special data for videos by default. This depends on the type of video steps you would like to have.<br>Take a closer look to examples to see how to add special data to describe steps."}
,"options":{
"docu":"options for video","series":{
"docu":"series options for videos","video":{
"docu":"video only options","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"take data from show specific serie for video, this needs to be overwritten in data ","defVal":"false"}
,"stepAction":{
"docu":"describes how the step should be shown. Default stephandling can be selected out of stepCollection:<br>default: appends information from data to a div or if no div given opens an alertbox<br>youtube: if a youtube id is given, the video is shown<br>a function name: the given function is called by handing over actual stepdata and seriesdata","defVal":"simple"}
,"stepCollection":{
"docu":"collection of predefined videosteps","simple":{
"docu":"default step giving information in a very simple way, see first example.","runStep":{
"docu":"Adds stepData to a div defined in walkPad","defVal":" addStepData(stepData,actionData)"}
,"walkPad":{
"docu":"target for addStepData","defVal":"#stepPad"}
,"walkTime":{
"docu":"Time for each step before walking to the next one","defVal":"2000"}
}
,"youtube":{
"docu":"opens and starts a video from youtube.<br>For this action a jQuery plugin from http://www.pittss.lv/jquery/gomap/index.php is used.","runStep":{
"docu":"shows a video in target defined in videoPad","defVal":" youtubeStep(stepData,actionData)"}
,"videoPad":{
"docu":"target for runStep","defVal":"#videoPad"}
,"width":{
"docu":"default width of video","defVal":"400"}
,"height":{
"docu":"default height of video","defVal":"300"}
,"maxDuration":{
"docu":"maximum duration of a video. Whatever happens first, end of video or end of maxDuration, stops actual step.","defVal":"20000"}
,"noVideoDuration":{
"docu":"Duration of step if no video information is available","defVal":"2000"}
}
}
}
}
}
}
}