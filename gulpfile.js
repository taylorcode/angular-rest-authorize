var gulp = require('gulp'),
    jasmine = require('gulp-jasmine'),
    babel = require('gulp-babel'),
    sourcemaps = require('gulp-sourcemaps'),
    concat = require('gulp-concat'),
    mainBowerFiles = require('main-bower-files'),
    mainBowerScripts = mainBowerFiles({dependencies: null, filter: function (filename) {
      return filename.match('.js$');
    }});

gulp.task('dev:scripts', function() {
    gulp.src('src/**/*.js') // throw vendor files in same file before souce files
        .pipe(sourcemaps.init())
        .pipe(babel())
        .pipe(concat('angular-rest-authorize.js'))
        .pipe(sourcemaps.write('.'))
        .pipe(gulp.dest('dist'));
});

 
gulp.task('dev:test', function () {
    return gulp.src('spec/test.js')
        .pipe(jasmine());
});

gulp.task('default', ['dev:scripts']);
