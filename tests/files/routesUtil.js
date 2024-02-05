/**
 * 路由配置、接口配置
 * @namespace  routesUtil
 * @name routesUtil
 */
define('routesUtil', ['zepto','bocAbroadRouterPath'], function($, bocAbroadRouterPath) {
    var _routerPath = {};
    _routerPath = $.extend(_routerPath,bocAbroadRouterPath.routerPath);
    var _services = {};
    _services = $.extend(_services,bocAbroadRouterPath.services);
    var _method = {};
    _method = $.extend(_method,bocAbroadRouterPath.method);
    return {
        routerPath:_routerPath,
        services:_services,
        method:_method
    };

});
