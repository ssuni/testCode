<?php

namespace App\Http\Middleware;

use App\Models\test;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class IsAdmin
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
        try{
            if(!Auth::user()){
                $request->merge(['isAdmin' => false]);
                return $next($request);
            }
            $channelId = $request->route('channelId');
            $channel = test::findOrFail($channelId);

            if($channel->member_uid == Auth::user()->uid){
                $request->merge(['isAdmin' => true]);
                return $next($request);
            }else{
                $request->merge(['isAdmin' => false]);
                return $next($request);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => 'error', 'message' => $e->getMessage()], 404);
        }
    }
}
