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

$.plot.JUMExample.docu.background = {
"docu":"Documentation","background":{
"docu":"<strong>Plugin to fraw background and/or overlay</strong>.<br>Background is drawn on an additional canvas context. Critical point is the use of zIndex, since some plugins change zIndex to negativ values.<br>See option zIndex how to handle this.","options":{
"docu":"","grid":{
"docu":"Standard grid object from Flot","background":{
"docu":"special options for background only","active":{
"docu":"activate the plugin","defVal":"false"}
,"mode":{
"docu":"optional values are image, color and userdefined","defVal":"color"}
,"color":{
"docu":"specific options for color mode","colors":{
"docu":"array of colors for color gradient","0":{
"docu":"","defVal":"white"}
,"1":{
"docu":"1st Color","defVal":"yellow"}
,"2":{
"docu":"2nd Color","defVal":"orange"}
,"3":{
"docu":"believe it or not, this is 3rd color ;-)","defVal":"blue"}
}
}
,"image":{
"docu":"specific options for image mode. This is set to an image object, see example for more details"}
,"fncDraw":{
"docu":"for calling userdefined backgrounds this is used for a function call. See examples with a clock running in the background"}
,"setZIndex":{
"docu":"option for setting all canvas to a specific value. Very helpful for using jQuery UI.<br>True sets background to 0, drawing area to 1 and highlight to 2<br>A number sets drawing area to the given number, background to number-- and highlight to number++ ","defVal":"false"}
}
,"overlay":{
"docu":"Specific options for drawing overlays. Overlay image is drawn on drawing area with given opacity.<br>This does not work for those plugins, that use hook draw","active":{
"docu":"Activates drawing an overlay","defVal":"false"}
,"image":{
"docu":"This is set to an image object, works similiar to image in background part"}
,"opacity":{
"docu":"Opacity for drawing overlay image","defVal":"0.2"}
}
}
}
}
}