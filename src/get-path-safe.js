module.exports = function getPathSafe(target, path){
    if(!target) return;
    path = path.split('.');
    var obj = target[path.shift()];
    while(obj && path.length) obj = obj[path.shift()];
    return obj;
};
