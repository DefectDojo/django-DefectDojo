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

$.plot.JUMExample.docu.bubbles = {
"docu":"","bubbles":{
"docu":"<strong>Plugin to create bubble charts</strong>","data":{
"docu":"Data Array specific for Bubbles chart","0":{
"docu":"first data entry","0":{
"docu":"Y-value, location of bubble"}
,"1":{
"docu":"X-value, location of value"}
,"2":{
"docu":"Size of bubble"}
}
}
,"options":{
"docu":"options for bubbles","series":{
"docu":"series options for bubbles","bubbles":{
"docu":"bubbles only options","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"show specific serie. this needs to be overwritten in data","defVal":"false"}
,"fill":{
"docu":"Fill bubbles","defVal":"true"}
,"lineWidth":{
"docu":"Line width of circle if fill is false","defVal":"2"}
,"highlight":{
"docu":"Used to highlight in case of HOVER","opacity":{
"docu":"only Opacity is supported for Highlighting (yet)","defVal":"0.5"}
}
,"drawbubble":{
"docu":"Function call which is used for drawing of one bar for Bubble. This can be replaced by user defined function. Take a closer look to source of examples to see more.","defVal":" drawbubbleDefault(ctx,serie,x,y,v,r,c,overlay)"}
,"bubblelabel":{
"docu":"Specific options how to show label in bubbles","show":{
"docu":"Switches labels on (or off)","defVal":"false"}
,"fillStyle":{
"docu":"Color of text","defVal":"black"}
}
}
,"editMode":{
"docu":"Default Editmode for bandwidth. See mouse plugin for more information."}
,"nearBy":{
"docu":"data used to support findItem for hover, click etc.","distance":{
"docu":"distance in pixel to find nearest bubble","defVal":"6"}
,"findMode":{
"docu":"Defines how find happens.","defVal":"circle"}
,"findItem":{
"docu":"Function call to find item under Cursor. Is overwritten during processRawData hook. This would be the place to add your own find function, which will not be overwritten.","defVal":" findNearbyItemDefault(mouseX,mouseY,i,serie)"}
,"drawEdit":{
"docu":"function to draw edit marker. It is defined in jquery.flot.mouse plugin, and is overwritten in plugin to support specific editmarkers","defVal":" drawEditDefault(octx,x,y,serie)"}
,"drawHover":{
"docu":"Function to draw overlay in case of hover a item. Is overwritten during processRawData hook. This would be the place to add your own hover drawing function.","defVal":" drawHoverDefault(octx,serie,dataIndex)"}
}
}
}
,"defVal":"none"}
,"defVal":""}