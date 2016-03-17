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

$.plot.JUMExample.docu.gantt = {
"docu":"Documentation","gantt":{
"docu":"<strong>Plugin to create gantt charts</strong>","data":{
"docu":"Data Array specific for gantt chart","0":{
"docu":"first dataset for chart","0":{
"docu":"Start of Step"}
,"1":{
"docu":"number of resource"}
,"2":{
"docu":"End of step"}
,"3":{
"docu":"Name for step (used for tooltip)"}
}
}
,"options":{
"docu":"options (general object from FLOT)","series":{
"docu":"options.series (general object from FLOT)","gantt":{
"docu":"specific options for gantt plugin","active":{
"docu":"Activates the gantt Plugin","defVal":"false"}
,"show":{
"docu":"Switches on/off the gantt for actual serie of data. Works only, if plugin is activated.","defVal":"false"}
,"connectSteps":{
"docu":"Describes connection lines from steps in one resource to a step in another.Its done by searching for steps in same serie which start at the same time another step ends.","show":{
"docu":"switches connection lines on","defVal":"false"}
,"lineWidth":{
"docu":"describes the width of connection line","defVal":"2"}
,"color":{
"docu":"color of connection line","defVal":"rgb(0,0,0)"}
}
,"barHeight":{
"docu":"Height of the bar compared to available space (1.0 would be full size)","defVal":"0.6"}
,"highlight":{
"docu":"Describes how highlighting (in case of HOVER) is displayed","opacity":{
"docu":"Default for highlighting is to change opacity only","defVal":"0.5"}
}
,"drawstep":{
"docu":"","defVal":" drawStepDefault(ctx,series,data,x,y,x2,color, isHighlight)"}
}
,"editMode":{
"docu":"defines in which direction editing could happen. optional values are: x,y,xy,v. This value is changed by the plugin, depending on the way you select a timebar (left, right or body)"}
,"nearBy":{
"docu":"ata used to support findItem for hover, click etc.","distance":{
"docu":"maximum distance from data point to recognize a hit "}
,"findItem":{
"docu":"function to find nearby item. It is defined in jquery.flot.mouse plugin, and is overwritten in plugin to support specific find functions.","defVal":" findNearbyItemDefault(mouseX,mouseY,i,serie)"}
,"findMode":{
"docu":"mode to find nearby item. Values are circle, vertical and horizontal"}
,"drawEdit":{
"docu":"function to draw edit marker. It is defined in jquery.flot.mouse plugin, and is overwritten in plugin to support specific editmarkers","defVal":" drawEditDefault(octx,x,y,serie)"}
,"drawHover":{
"docu":"function to draw hover shadow. It is defined in jquery.flot.mouse plugin.","defVal":" drawHoverDefault(octx,serie,dataIndex)"}
}
}
}
}
}