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

$.plot.JUMExample.docu.contour = {
"docu":"Documentation","contour":{
"docu":"<strong>Plugin to create bandwidth charts</strong>","data":{
"docu":"Data Array specific for contour chart","0":{
"docu":"first data entry","0":{
"docu":"X-position"}
,"1":{
"docu":"Y-position"}
,"2":{
"docu":"Width of contour"}
,"3":{
"docu":"height of contour"}
,"4":{
"docu":"angle of whole contour"}
}
}
,"options":{
"docu":"options for contour","series":{
"docu":"series options for contour","contour":{
"docu":"contour only options","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"show specific serie. this needs to be overwritten in data","defVal":"false"}
,"ellipseStep":{
"docu":"drawing of contour ellipse is based on code found in the internet. There was no author, so if you are the one, please give me a hint.<br><br>ellipseStep is used to define how perfect the ellipse should be, take a higher value to see what this means","defVal":"0.1"}
}
,"nearBy":{
"docu":"data used to support findItem for hover, click etc.<br><br>this part is not tested very well yet and needs to be rebuilt","distance":{
"docu":"distance in pixel to find nearest contour"}
,"findItem":{
"docu":"Function call to find item under Cursor. Is overwritten during processRawData hook. This would be the place to add your own find function, which will not be overwritten."}
,"findMode":{
"docu":"Defines how find happens."}
,"drawHover":{
"docu":"Function to draw overlay in case of hover a item. Is overwritten during processRawData hook. This would be the place to add your own hover drawing function."}
}
}
}
}
}