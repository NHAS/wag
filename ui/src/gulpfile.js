"use strict";

// Load plugins
const autoprefixer = require("gulp-autoprefixer");
const cleanCSS = require("gulp-clean-css");
const gulp = require("gulp");
const del = require("del");
const header = require("gulp-header");
const merge = require("merge-stream");
const plumber = require("gulp-plumber");
const rename = require("gulp-rename");
const sass = require('gulp-sass')(require('sass'));
const uglify = require("gulp-uglify");

// Load package.json for banner
const pkg = require('./package.json');

// Set the banner content
const banner = ['/*!\n',
  ' * Wag UI - <%= pkg.title %> v<%= pkg.version %> (<%= pkg.homepage %>)\n',
  ' * Copyright 2013-' + (new Date()).getFullYear(), ' <%= pkg.author %>\n',
  ' */\n',
  '\n'
].join('');


// Clean vendor
function clean() {
  return del(["../vendor/", "../css", "../js"], { force: true });
}

// Bring third party dependencies from node_modules into vendor directory
function modules() {
  // Bootstrap JS
  var bootstrapJS = gulp.src('./node_modules/bootstrap/dist/js/*')
    .pipe(gulp.dest('../vendor/bootstrap/js'));
  // Bootstrap SCSS
  var bootstrapSCSS = gulp.src('./node_modules/bootstrap/scss/**/*')
    .pipe(gulp.dest('../vendor/bootstrap/scss'));

  // Bootstrap Table
  var bootstrapTableJS = gulp.src(['./node_modules/bootstrap-table/dist/bootstrap-table.min.js',
    './node_modules/bootstrap-table/dist/bootstrap-table-locale-all.min.js'])
    .pipe(gulp.dest('../vendor/bootstrap-table/js'));

  var bootstrapTableCSS = gulp.src('./node_modules/bootstrap-table/dist/bootstrap-table.min.css')
    .pipe(gulp.dest('../vendor/bootstrap-table/css'));

  var jqueryEasing = gulp.src('./node_modules/jquery.easing/*.min.js')
    .pipe(gulp.dest('../vendor/jquery-easing'));
  // jQuery
  var jquery = gulp.src([
    './node_modules/jquery/dist/*.min.*',
    '!./node_modules/jquery/dist/core.js'
  ])
    .pipe(gulp.dest('../vendor/jquery'));
  return merge(bootstrapJS, bootstrapSCSS, bootstrapTableJS, bootstrapTableCSS, jquery, jqueryEasing);
}

// SCSS task
function scss() {
  return gulp
    .src("./scss/**/*.scss")
    .pipe(plumber())
    .pipe(sass({
      outputStyle: "expanded",
      includePaths: "./node_modules",
    }))
    .on("error", sass.logError)
    .pipe(autoprefixer({
      cascade: false
    }))
    .pipe(header(banner, {
      pkg: pkg
    }))
    .pipe(gulp.dest("./css"))
}

function css() {
  return gulp.src("./css/*.css")
    .pipe(gulp.dest("./css"))
    .pipe(rename({
      suffix: ".min"
    }))
    .pipe(cleanCSS())
    .pipe(gulp.dest("../css"))
}

// JS task
function js() {
  return gulp
    .src([
      './js/*.js',
      '!./js/*.min.js',
    ])
    .pipe(uglify())
    .pipe(header(banner, {
      pkg: pkg
    }))
    .pipe(rename({
      suffix: '.min'
    }))
    .pipe(gulp.dest('../js'))
}

// Define complex tasks
const vendor = gulp.series(clean, modules);
const csstasks = gulp.series(scss, css);
const build = gulp.series(vendor, gulp.parallel(csstasks, js));
// Export tasks
exports.css = css;
exports.js = js;
exports.clean = clean;
exports.vendor = vendor;
exports.build = build;
exports.default = build;
