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

$.plot.JUMExample.docu.candlestick = {
"docu":"Documentation","candlestick":{
"docu":"Plugin to show a candlestick chart","data":{
"docu":"Data Array specific for Bandwidth chart","0":{
"docu":"1st entry in data","0":{
"docu":"x-Position, usually a date"}
,"1":{
"docu":"Start-value, used for the body"}
,"2":{
"docu":"End-value, used for the body"}
,"3":{
"docu":"minimum value, used for the line"}
,"4":{
"docu":"maximum value, used for the line part"}
}
}
,"options":{
"docu":"options (general object from FLOT)","series":{
"docu":"series (general object from FLOT)","candlestick":{
"docu":"specific options for candlestick plugin","active":{
"docu":"switches binding of plugin into hooks","defVal":"false"}
,"show":{
"docu":"switches show of candlestick on for actual series","defVal":"false"}
,"rangeWidth":{
"docu":"range is displayed as line, this value is the width of this line","defVal":"4"}
,"rangeColor":{
"docu":"Color of line from min to max","defVal":"rgb(0,128,128)"}
,"upColor":{
"docu":"color of body from startvalue to endvalue if endvalue is greater than startvalue","defVal":"rgb(255,0,0)"}
,"downColor":{
"docu":"color of body from startvalue to endvalue if endvalue is less than startvalue","defVal":"rgb(0,255,0)"}
,"neutralColor":{
"docu":"color of body if startvalue is equal to endvalue","defVal":"rgb(0,0,0)"}
,"lineWidth":{
"docu":"Body is shown as a line, this is the size of the line","defVal":"8px"}
,"highlight":{
"docu":"Describes how highlighting (in case of HOVER) is displayed","opacity":{
"docu":"Default for highlighting is to change opacity only","defVal":"0.5"}
}
,"drawCandlestick":{
"docu":"Default function to display each candlestick. This can be overwritten. Please see function mydraw in source of examples page","defVal":" drawCandlestickDefault(ctx,serie,data,hover)"}
}
,"editMode":{
"docu":"defines in which direction editing could happen. optional values are: x,y,xy,v"}
,"nearBy":{
"docu":"data used to support findItem for hover, click etc.","distance":{
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