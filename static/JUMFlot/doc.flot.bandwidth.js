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

$.plot.JUMExample.docu.bandwidth = {
"docu":"","defVal":"","bandwidth":{
"docu":"<strong>Plugin to create bandwidth charts</strong>","defVal":"none","data":{
"docu":"Data Array specific for Bandwidth chart","defVal":"none","0":{
"docu":"first data entry","defVal":"none","0":{
"docu":"Y-value","defVal":"none"}
,"1":{
"docu":"X High-value","defVal":"none"}
,"2":{
"docu":"X Low-value","defVal":"none"}
}
,"1":{
"docu":"more entries","defVal":"none"}
}
,"options":{
"docu":"options for bandwidth","defVal":"none","series":{
"docu":"series options for bandwidth","defVal":"none","bandwidth":{
"docu":"bandwidth only options","defVal":"none","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"show specific serie. this needs to be overwritten in data","defVal":"false"}
,"fill":{
"docu":"Fill bandwidth bar, (false not checked yet)","defVal":"true"}
,"lineWidth":{
"docu":"The linewidth of a bandwidth bar, given as number and px(see default) others formats will follow later","defVal":"4px"}
,"highlight":{
"docu":"Used to highlight in case of HOVER","defVal":"none","opacity":{
"docu":"only Opacity is supported for Highlighting (yet)","defVal":"0.5"}
}
,"drawBandwidth":{
"docu":"Function call which is used for drawing of one bar for Bandwidth. This can be replaced by user defined function. Take a closer look to source of examples to see more.","defVal":"none"}
}
,"editMode":{
"docu":"Default Editmode for bandwidth. See mouse plugin for more information. This value may be overdriven during editing, to support changing of X(can be changed in X-direction only), High and Low(both can be changed in Y-direction only).","defVal":"y"}
,"editable":{
"docu":"copied by FLOT, source is mouse plugin","defVal":"false"}
,"nearBy":{
"docu":"data used to support findItem for hover, click etc.","defVal":"none","distance":{
"docu":"distance in pixel to find nearest bandwidth bar","defVal":"6"}
,"findItem":{
"docu":"Function call to find item under Cursor. Is overwritten during processRawData hook. This would be the place to add your own find function, which will not be overwritten.","defVal":"null"}
,"findMode":{
"docu":"Defines how find happens.","defval":"circle"}
,"drawHover":{
"docu":"Function to draw overlay in case of hover a item. Is overwritten during processRawData hook. This would be the place to add your own hover drawing function.","defVal":"null"}
}
}
,"grid":{
"docu":"Grid specific data, which is supported in bandwidth plugin.","defVal":"none","clickable":{
"docu":"switch support for click event on or off","defVal":"none"}
,"hoverable":{
"docu":"switch support for hover event on or off","defVal":"none"}
,"editable":{
"docu":"switch editing of bandwith data on or off","defVal":"false"}
}
}
}
}