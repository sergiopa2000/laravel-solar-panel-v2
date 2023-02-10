<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use JWTAuth;
use Illuminate\Support\Facades\Validator;
use function MNC\Http\fetch;
use App\Models\User;

class ApiAuthController extends Controller
{
    function __construct(){
        $this->middleware('jwt.verify')->only(['request', 'logout']);
    }
    
    public function register(Request $request){
        $validator = Validator::make($request->only('name', 'email', 'password'), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);
        
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'user' => $user
        ]);
    }
    
    public function login(Request $request) {
        $validator = Validator::make($request->only('email', 'password'), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
        
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }
        
        $credentials = $request->only('email', 'password');
        $token = JWTAuth::attempt($credentials);
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }
        
        $payload = JWTAuth::setToken($token)->getPayload();
        $expires_at = Carbon::parse($payload->get('exp'))->addHour()->format('d M Y H:i'); 

        $user = Auth::user();
        return response()->json([
                'status' => 'success',
                'user' => $user,
                'authorization' => [
                    'token' => $token,
                    'type' => 'Bearer',
                    'expires_at' => $expires_at
                ]
            ]);
    }
    
    public function logout(Request $request){
        $token = $request->bearerToken();
		//Request is validated, do logout  
		if(!$token){
            return response()->json([
                'success' => false,
                'message' => 'You must provide a token'
            ], 402);
		}
		
        try {
            JWTAuth::setToken($token);
            JWTAuth::invalidate($request->bearerToken());
 
            return response()->json([
                'success' => true,
                'message' => 'User has been logged out'
            ], 200);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, user cannot be logged out'
            ], 500);
        }
    }
    
    public function request(){
        $url = 'https://api.sunrise-sunset.org/json?lat=37.1881700&lng=-3.6066700&date='.date('Y-m-d').'&formatted=0';
        $json = json_decode(file_get_contents($url));
        $sunrise = $json->results->sunrise;
        $sunrise = explode('T', $sunrise);
        $sunrise = explode('+', $sunrise[1]);
        $sunrise = explode(':', $sunrise[0]);
        $sunrise = intval($sunrise[0]) * 60 + intval($sunrise[1]);
        
        $sunset = $json->results->sunset;
        $sunset = explode('T', $sunset);
        $sunset = explode('+', $sunset[1]);
        $sunset = explode(':', $sunset[0]);
        $sunset = intval($sunset[0]) * 60 + intval($sunset[1]);
        
        $variableNumber = (intval(date('H')) * 60) + (intval(date('i')));
        if($variableNumber < $sunrise || $variableNumber > $sunset){ //  Si está fuera del rango devolvemos 0
            $cos = 0;
            $sen = 0;
        }else{
            $interpolated = ((($variableNumber - $sunrise)*((pi() / 2) - (-pi() / 2))) / ($sunset - $sunrise)) + (-pi() / 2);
            $cos = cos($interpolated);
            $sen = sin($interpolated);
        }

        return response()->json(
            [
            'cos' => round($cos, 10), 
            'sen' => $sen, 
            'sensor1' => rand(0, 1),
            'sensor2' => rand(0, 1),
            'sensor3' => rand(0, 1),
            'sensor4' => rand(0, 1),
            ], 401);
    }
}