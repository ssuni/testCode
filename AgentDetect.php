<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Jenssegers\Agent\Agent;

class AgentDetect
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        $agent = new Agent();
        $platform = $agent->platform();
        if (preg_match('/PostmanRuntime/i', $request->header('User-Agent'))) {
            $platform = 'Postman';
        }
        $mobileResult = $agent->isMobile();
        if ($mobileResult) {
            $platform = 'Mobile';
        }

        $desktopResult= $agent->isDesktop();
        if ($desktopResult) {
            $platform = 'Desktop';
        }

        $tabletResult= $agent->isTablet();
        if ($tabletResult) {
            $platform = 'Tablet';
        }

        $phoneResult= $agent->isPhone();
        if ($phoneResult) {
            if($agent->isAndroidOS()) {
                $platform = 'ANDROID';
            }else if($agent->isIOS()) {
                $platform = 'IOS';
            }else {
                $platform = 'Phone';
            }
        }
        $request->merge(['platform' => $platform]);
        return $next($request);
    }
}
