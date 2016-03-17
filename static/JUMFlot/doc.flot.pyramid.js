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

$.plot.JUMExample.docu.pyramids = {
"docu":"Documentation","pyramid":{
"docu":"Plugin to create pyramids charts","data":{
"docu":"Data Array specific for pyramids chart","0":{
"docu":"first data entry","value":{
"docu":"Value(size) for data slice"}
,"label":{
"docu":"Label of the data clice"}
}
}
,"options":{
"docu":"options for pyramids","series":{
"docu":"series options for pyramids","pyramids":{
"docu":"pyramids only options","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"how specific serie. this needs to be overwritten in data","defVal":"false"}
,"mode":{
"docu":"Decribes how a slice is shown. Actually pyramid and slice are supported","defVal":"pyramid"}
,"fill":{
"docu":"Switches Fillmode for drawing of a slice","defVal":"true"}
,"highlight":{
"docu":"Used to highlight in case of HOVER","opacity":{
"docu":"only Opacity is supported for Highlighting (yet)","defVal":"0.5"}
}
,"label":{
"docu":"description whether and how a label should be drawn","show":{
"docu":"Swichtes label drawing on or off","defVal":"false"}
,"align":{
"docu":"Position of label","defVal":"center"}
,"font":{
"docu":"Used font for Label","defVal":"20px Times New Roman"}
,"fillStyle":{
"docu":"Default color for label","defVal":"Black"}
}
}
,"editMode":{
"docu":"comin form mouse plugin, is nonsense for this plugin, since edit is not supported"}
,"nearBy":{
"docu":"Defines how nearby is used to find item under mouse","distance":{
"docu":"distance in pixel to find nearest slyce","defVal":"6"}
,"findItem":{
"docu":"Function call to find item under Cursor. Is overwritten during processRawData hook. This would be the place to add your own find function, which will not be overwritten."}
,"findMode":{
"docu":"Defines how find happens.","defVal":"circle"}
,"drawHover":{
"docu":"Function to draw overlay in case of hover a item. Is overwritten during processRawData hook. This would be the place to add your own hover drawing function."}
,"drawEdit":{
"docu":"not used","defVal":" drawEditDefault(octx,x,y,serie)"}
}
}
}
}
}