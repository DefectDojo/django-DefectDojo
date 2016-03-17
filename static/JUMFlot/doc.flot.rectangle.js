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

$.plot.JUMExample.docu.rectangle = {
"docu":"Documentation","rectangle":{
"docu":"Plugin to create rectangle charts","data":{
"docu":"Data Array specific for rectangle chart","0":{
"docu":"first data entry","label":{
"docu":"standard label"}
,"data":{
"docu":"standard in flot"}
,"pos":{
"docu":"plugin internal cache for later support of hover etc","x":{
"docu":"x-position"}
,"y":{
"docu":"y-position"}
,"w":{
"docu":"width"}
,"h":{
"docu":"height"}
,"color":{
"docu":"guess yourself, what this could be :-)"}
}
}
}
,"options":{
"docu":"options for rectangle","series":{
"docu":"series options for rectangle","rectangle":{
"docu":"rectanle only options","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"show specific serie. this needs to be overwritten in data","defVal":"false"}
,"fill":{
"docu":"rectangle to be filled (or not)","defVal":"true"}
,"lineWidth":{
"docu":"linewidth for border of rectangle","defVal":"2"}
,"directions":{
"docu":"array of direction how the rectangles should be drawn on screen. Should not be empty. Optional values are:<br>t for top, l for left, b for bottom and r for right.<br>For example taking tl would draw first rectangle from top of empty drawing are down to bottom, next would start on left of empty area and going to the right.","defVal":"tlbr"}
,"highlight":{
"docu":"Used to highlight in case of HOVER","opacity":{
"docu":"only Opacity is supported for Highlighting (yet)","defVal":"0.5"}
}
,"drawRectangle":{
"docu":"default drawing callback for each rectangle. Can be overwritten by userdefined function","defVal":" drawRectangleDefault(ctx,serie,dataIndex)"}
,"label":{
"docu":"defines whether / how labels are shown","show":{
"docu":"show labels or not","defVal":"false"}
,"fillStyle":{
"docu":"color of labeltext","defVal":"black"}
}
}
,"editMode":{
"docu":"Default Editmode for Rectangle. See mouse plugin for more information."}
,"nearBy":{
"docu":" data used to support findItem for hover, click etc.","distance":{
"docu":"distance in pixel to find nearest rectangle","defVal":"6"}
,"findMode":{
"docu":"Defines how find happens.","defVal":"circle"}
,"findItem":{
"docu":" Function call to find item under Cursor. Is overwritten during processRawData hook. This would be the place to add your own find function, which will not be overwritten.","defVal":" findNearbyItemDefault(mouseX,mouseY,i,serie)"}
,"drawEdit":{
"docu":"Not supported for rectangle","defVal":" drawEditDefault(octx,x,y,serie)"}
,"drawHover":{
"docu":"Function to draw overlay in case of hover a item. Is overwritten during processRawData hook. This would be the place to add your own hover drawing function.","defVal":" drawHoverDefault(octx,serie,dataIndex)"}
}
}
}
}
}