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

$.plot.JUMExample.docu.grow = {
"docu":"Documentation","grow":{
"docu":"Plugin to support animation of charts","data":{
"docu":"Data Array specific for Bandwidth chart","0":{
"docu":"first data entry","0":{
"docu":"Y-value"}
,"1":{
"docu":"X-value"}
}
}
,"options":{
"docu":" options for grow","series":{
"docu":"series options for grow","grow":{
"docu":"grow only options","active":{
"docu":"activate the plugin","defVal":"true"}
,"valueIndex":{
"docu":"which part of data should be used for growing. Usually it is the X-Value which has index and therefor is 2nd value ","defVal":"1"}
,"stepDelay":{
"docu":"delay between 2 steps in millisecs. Depending on the power of your brower/computer the time to draw a chart has to be added.","defVal":"20"}
,"steps":{
"docu":"Defines how many seperate steps will be shown from beginning to end","defVal":"100"}
,"stepMode":{
"docu":"defines how each step is performed. Options are linear (step by step, everything is growing to the end), maximum (grow until value is reached, growing stops earlier for smaller values) and delayed (nothing and start later)","defVal":"linear"}
,"stepDirection":{
"docu":"direction of steps up(from 0 to value) or down(from axis.max to value)","defVal":"up"}
}
,"editMode":{
"docu":"not supported"}
,"nearBy":{
"docu":"not supported"}
}
}
}
}