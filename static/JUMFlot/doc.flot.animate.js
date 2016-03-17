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

$.plot.JUMExample.docu.animate = {
"docu":"Documentation","animate":{
"docu":"<strong>Plugin to handle simple animations charts</strong>","options":{
"docu":"Options object from Flot","animate":{
"docu":"Animate specific options","active":{
"docu":"activate the plugin","defVal":"false"}
,"mode":{
"docu":"Mode of animation. Right now tile and pixastic are supported.<br><br>Tile splits the drawing in tiles and draws them based on tile options","defVal":"tile"}
,"tile":{
"docu":"Tile specif options for animate","x":{
"docu":"Number of tiles in x direction","defVal":"3"}
,"y":{
"docu":"Number of tiles in y direction","defVal":"3"}
,"mode":{
"docu":"Describes, how tiles are drawn<br><br>lt: starting on left, top, columns first, then rows<br><br>tl: starting on left, top, rows first then coumns<br><br>rb: starting bottom right, columns first then rows<br><br>br: starting bottom right, rows first then columns<br><br>random: draws tile by randomized function","defVal":"lt"}
}
,"pixastic":{
"docu":"Specific option for using pixastic library, see www.pixastic.com for more information about this library. Only a few options of this powerful library are taken for animate.","maxValue":{
"docu":"Value between -1 and +1<br><br>defines how strong the deformation should start.","defVal":"1"}
,"mode":{
"docu":"Name of pixastic functions:<br><br>blurfast<br><br>lighten<br><br>emboss<br><br>mosaic<br><br>noise","defVal":"blurfast"}
}
,"stepDelay":{
"docu":"Delay in mille secs between steps in pixastic or before drawing next tile","defVal":"500"}
,"steps":{
"docu":"Number of steps, used for pixastic only","defVal":"20"}
}
}
}
}