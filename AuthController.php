<?php

  namespace App\Http\Controllers;

  use Illuminate\Http\Request;
  use Illuminate\Support\Facades\Auth;
  use Illuminate\Support\Facades\Hash;
  use App\Models\User;
  use Illuminate\Support\Facades\Log;
  use Illuminate\Support\Facades\Validator;
  use Laravel\Socialite\Facades\Socialite;
  use App\Services\UserService;
  use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;

  class AuthController extends Controller
  {
    private UserService $userService;
    public function __construct(UserService $userService)
    {
      $this->middleware('auth:api',
        [
          'except' => [
            'login', 'register', 'userProfile', 'refresh', 'kakao', 'kakaoCallback',
            'naver', 'naverCallback', 'usableEmail', 'usableNickname', 'registerDeviceId'
          ]
        ]
      );
      $this->userService = $userService;
    }

    public function registerDeviceId(Request $request)
    {
      try {

        $remote_addr = $request->ip();
        $oldDeviceId = $request->input('old_device_id');
        $newDeviceId = $request->input('device_id');
        $os = $request->input('os');

        $error_code = 0;
        $error_msg = '';
        $member = array();

        if (empty($oldDeviceId) || empty($newDeviceId) || empty($os)) {
          $error_code = 999;
        }

        if (isset($os)) {
          $os = (strtolower($os) == 'ios') ? 'iOS' : 'Android';
        }

        if ($error_code === 0) {
          // 신규 device id 로 등록된 기기가 있는지 체크
          $checkDeviceId = $this->userService->checkDeviceId($newDeviceId);

          if (!empty($checkDeviceId)) {
            $member = $checkDeviceId;
          }
        }

        if (empty($member) && $error_code === 0) {
          // 기존 등록된 기기가 있는지 체크

          $checkDevice = $this->userService->checkDevice($oldDeviceId);

          // 등록된 기기가 없는 경우 신규 등록
          if (empty($checkDevice)) {
            // 등록된 device id 가 없는 경우 신규 등록
            $auth_code = sha1('pbma'.date('YmdHis'));

            // test_member에 등록
            $memberUid = $this->userService->registerDevice($newDeviceId, $auth_code, 'M');

            if ($memberUid) {
              // test_member_app에 등록
              $memberAppUid = $this->userService->registerDeviceApp($memberUid, $newDeviceId, $os, $auth_code);

              if ($memberAppUid) {
                $member['id'] = $memberAppUid;
                $member['authCode'] = $auth_code;
              } else {
                $error_code = 999;
              }

            } else {
              $error_code = 999;
            }
          }
        }

        if (empty($member) && $error_code === 0) {
          // 중복된 device id 가 있는 경우 최근 등록된 device id 를 제외하고 사용 중지 처리
          if (count($checkDeviceId) > 1) {
            $this->userService->updateDuplicateDeviceStatus($oldDeviceId,$memberAppUid);
          }

          // 신규 device id 로 업데이트
          $deviceInfo = $this->userService->updateDevice($newDeviceId, $memberAppUid);

          if ($deviceInfo) {
            $member['id'] = $memberAppUid;
            $member['authCode'] = $deviceInfo['auth_code'];
          } else {
            $error_code = 999;
          }

          $response['error']	= array(
            'code' => $error_code,
            'message' => $error_msg
          );

          $response['member']	= $member;

          return $response;
        }


        return $member;
      } catch (\Exception $e) {
        Log::error('AuthController registerDeviceId: '.$e->getMessage());
        return response()->json(['error' => $e->getMessage()], 500);
      }
    }

    public function login(Request $request)
    {
      try {
        $validator = Validator::make($request->all(), [
          'email' => 'required|email',
          'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
          return response()->json(['error' => '입력 필드값 오류!'], 422);
        }
        $user = User::where([
          'email' => $request->email,
          'passwd' => hash('sha512', $request->password)
        ])->first();

        if ($user) {
          $token = Auth::login($user);
        }

        if (!$token) {
          return response()->json([
            'status' => 'error',
            'message' => 'Unauthorized',
          ], 401);
        }
        $cash = $this->userService->getCashByMemberUid($user->uid);
        $cash =  array(
          'charge' => $cash->pay_charge,
          'free' => $cash->pay_free,
          'reward' => 0,
          'total' => $cash->pay_charge + $cash->pay_free
        );

        $user = Auth::user();
        $user->cash = $cash;
        $user->adult = $user->certify == 'CA';

        return response()->json([
          'status' => 'success',
          'user' => $user,
          'authorisation' => [
            'token' => $token,
            'type' => 'bearer',
          ]
        ]);
      } catch (\Exception $e) {
        Log::error('AuthController login: '.$e->getMessage());
        return response()->json(['error' => $e->getMessage()], 500);
      }

    }

    public function register(Request $request)
    {
      try {
        $request->validate([
          'name' => 'required|string|max:255',
          'email' => 'required|string|email|max:255|unique:users',
          'password' => 'required|string|min:6',
        ]);

        $user = User::create([
          'name' => $request->name,
          'email' => $request->email,
          'passwd' => hash('sha512', $request->password),
//            'passwd' => bcrypt($request->password),
        ]);

        $token = Auth::login($user);
        return response()->json([
          'status' => 'success',
          'message' => 'User created successfully',
          'user' => $user,
          'authorisation' => [
            'token' => $token,
            'type' => 'bearer',
          ]
        ]);
      } catch (\Exception $e) {
        Log::error('AuthController register: '.$e->getMessage());
        return response()->json(['error' => $e->getMessage()], 500);
      }
    }

    public function logout()
    {
      try {
        Auth::logout();
        return response()->json([
          'status' => 'success',
          'message' => 'Successfully logged out',
        ]);
      } catch (\Exception $e) {
        Log::error('AuthController logout: '.$e->getMessage());
        return response()->json([
          'status' => 'error',
          'message' => 'Failed to logout',
        ], 500);
      }
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile()
    {
      try {
        $user = Auth::user();
        if(!$user) {
          return response()->json([
            'status' => 'error',
            'message' => 'Unauthorized',
          ], 401);
        }
        return response()->json(auth()->user());
      } catch (\Exception $e) {
        Log::error('AuthController userProfile: '.$e->getMessage());
        return response()->json(['error' => '로그인이 필요합니다.'], 401);
      }
    }

    public function refresh()
    {
      try {
        return response()->json([
          'status' => 'success',
          'user' => Auth::user(),
          'authorisation' => [
            'token' => Auth::refresh(),
            'type' => 'bearer',
          ]
        ]);
      } catch (\Exception $e) {
        Log::error('AuthController refresh: '.$e->getMessage());
        return response()->json([
          'status' => 'error',
          'message' => 'Token refresh failed',
          'error' => $e->getMessage(),
        ], 500);
      }
    }

    /**
     * Get the token array structure.
     *
     * @param  string  $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
      return response()->json([
        'success' => true,
        'access_token' => $token,
        'token_type' => 'bearer',
        'expires_in' => auth()->factory()->getTTL() * 60,
//            'expires_in' =>  1440,
        'user' => auth()->user()
      ]);
    }

    public function kakao()
    {
      return Socialite::driver('kakao')->stateless()->redirect();
    }

    public function kakaoCallback()
    {
      $user = Socialite::driver('kakao')->stateless()->user();
      return response()->json($user);
    }

    public function naver()
    {
      return Socialite::driver('naver')->stateless()->redirect();
    }

    public function naverCallback()
    {
      $user = Socialite::driver('naver')->stateless()->user();
      return response()->json($user);
    }

    //Todo facebook, twitter, apple https 적용

    public function usableEmail(Request $request)
    {
      try {
        $email = $request->email;

        if (!$email) {
          throw new \Exception('잘못된 요청입니다.');
        }

        if ($this->userService->getByEmail($email)) {
          throw new \Exception('이미 사용중인 이메일입니다.', 210);
        }

        if ($this->userService->getByEmailUserDormant($email)) {
          throw new \Exception('이미 사용중인 이메일입니다.', 220);
        }

        $response = (object) array('usableEmail' => true);

        return response()->json($response);

      } catch (\Exception $e) {
        Log::error('AuthController usableEmail: '.$e->getMessage());
        return match ($e->getCode()) {
          210 => response()->json(['error' => $e->getMessage(), 'type' => 'ALREADY_USE_EMAIL'], 210),
          220 => response()->json(['error' => $e->getMessage(), 'type' => 'DORMANT_ACCOUNT'], 220),
          default => response()->json(['error' => $e->getMessage(), 'type' => 'DATABASE_ERROR'], $e->getCode()),
        };
      }
    }

    public function usableNickname(Request $request)
    {
      try {
        $nickname = $request->nickname;

        if (!preg_match($this->PREG_NICKNAME, $nickname)) {
          throw new \Exception('잘못된 요청입니다.', 210);
        }

        if ($this->userService->hasProhibitedWord($nickname)) {
          throw new \Exception('사용할 수 없는 닉네임입니다.', 220);
        }

        if ($this->userService->getByName($nickname)) {
          throw new \Exception('이미 사용중인 닉네임입니다.', 230);
        }

        if ($this->userService->getByNameUserDormant($nickname)) {
          throw new \Exception('이미 사용중인 닉네임입니다.', 240);
        }
        $response = (object) array('usableNickname' => true);

        return response()->json($response);

      } catch (\Exception $e) {
        Log::error('AuthController usableNickname: '.$e->getMessage());
        return match ($e->getCode()) {
          210 => response()->json(['error' => $e->getMessage(), 'type' => 'INVALID_NICKNAME'], 210),
          220 => response()->json(['error' => $e->getMessage(), 'type' => 'HAS_PROHIBITED_WORD'], 220),
          230 => response()->json(['error' => $e->getMessage(), 'type' => 'ALREADY_USE_NICKNAME'], 220),
          240 => response()->json(['error' => $e->getMessage(), 'type' => 'DORMANT_ACCOUNT'], 220),
          default => response()->json(['error' => $e->getMessage(), 'type' => 'DATABASE_ERROR'], $e->getCode()),
        };
      }
    }

    public function createSmsCertify(Request $request)
    {
      try {
        $expires = $request->input('expires', $this->_DEFAULT_EXPIRES);
        $countryCode = $request->input('countryCode');
        $phone = $request->input('phone', null);

        if (!Auth::user()) {
          throw new \Exception('로그인이 필요합니다.', 401);
        }
        $since = date('Y-m-d 00:00:00');
        $until = date('Y-m-d 23:59:59');

        $certifyCount = $this->userService->getCertifyCount($type = 'SMS', $phone, $since, $until);

        // 1일 최대 전송 횟수를 초과한 경우 예외처리
        if ($certifyCount >= $this->_MAX_SEND_COUNT_DAILY) {
          throw new \Exception('일일 인증 가능 횟수 '.$this->_MAX_SEND_COUNT_DAILY.'회를 초과하셨습니다.');
        }

        // 인증 내역 생성
        $authCode = sprintf('%06d', rand(000000, 999999));
        $message = sprintf($this->_AUTH_MESSAGE, $authCode);

        $this->userService->createCertify($type = 'SMS', $phone, $authCode, $expires, Auth::user()->uid);

        $sendResult = $this->userService->sendSMSBySureM($countryCode, '010-123-1234', $message);

        // 문자 발송 실패 시 예외처리
        if (!isset($sendResult[0]->result) || $sendResult[0]->result != 'success') {
          throw new \Exception("인증 실패하였습니다. 해외 인증은 통신 품질 문제가 존재할 수 있으며 지속되는 경우 1:1문의를 통해 인증을 요청해주십시오.");
        }

        $response = array(
          'success' => 1,
          // 'auth_code' => $authCode
        );

        return response()->json($response);

      } catch (\Exception $e) {
        Log::error('AuthController createSmsCertify: '.$e->getMessage());
        return response()->json(['error' => $e->getMessage()]);
      }
    }

    public function authorizeCertify(Request $request, $authCode)
    {
      try {
        $type = $request->input('type', 'SMS');
        $key = $request->input('key');

        if (!$authCode) {
          throw new \Exception('인증 코드 정보가 없습니다.');
        }
        if (!$type) {
          throw new \Exception('인증 타입 정보가 없습니다.');
        }
        if (!$key) {
          throw new \Exception('인증 키 정보가 없습니다.');
        }

        $status = 'I';

        $certifyLog = $this->userService->getCertifyLog($type, $key, $status);

        if (!$certifyLog) {
          throw new \Exception('인증 정보가 존재하지 않습니다.');
        }

        if ($certifyLog['code'] != $authCode) {
          throw new \Exception('인증 코드가 일치하지 않습니다.');
        }

        $this->userService->updateCertifyLog($certifyLog['uid'], 'U', date('Y-m-d H:i:s'));

        $response = (object) array('success' => 1);

        return response()->json($response);

      } catch (\Exception $e) {
        Log::error('AuthController authorizeCertify: '.$e->getMessage());
        return response()->json(['error' => $e->getMessage()]);
      }
    }
  }
