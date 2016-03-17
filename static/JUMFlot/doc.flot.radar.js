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

$.plot.JUMExample.docu.radar = {
"docu":"Documentation","radar":{
"docu":"<strong>Plugin to create spider chart</strong>","data":{
"docu":"Data Array specific for Spider chart","0":{
"docu":"first data entry","0":{
"docu":"Angle of datapoint in degrees(1-360)"}
,"1":{
"docu":"Size of datapoint"}
}
}
,"options":{
"docu":"options for Radar","series":{
"docu":"series options for Radar","radar":{
"docu":"Radar only options","active":{
"docu":"activate the plugin","defVal":"false"}
,"show":{
"docu":"show specific serie. this needs to be overwritten in data","defVal":"false"}
,"radarSize":{
"docu":"size of radar screen relative to size of placeholder","defVal":"0.8"}
,"delay":{
"docu":"Delay in ms between redrawing on next position","defVal":"10"}
,"angleStep":{
"docu":"stepsize to next position in degrees(0-360). Do not use big numbers here, for testing start below 100","defVal":"1"}
,"angleSize":{
"docu":"Size of each sub radar beam. Use userdefined screen for testing.","defVal":"10"}
,"angleSteps":{
"docu":"Number of sub radar beams. Values up to 9 are useful.","defVal":"6"}
,"color":{
"docu":"Beam Color","defVal":"darkgreen"}
,"backColor":{
"docu":"Color of background","defVal":"darkgreen"}
}
}
}
}
}