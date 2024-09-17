import { useUserStore } from "@/stores/user-store/user-store";
import axios, { AxiosError, AxiosResponse } from "axios";
import { v4 as uuidv4 } from "uuid";
import Cookies from "js-cookie";
import { AuthRefreshReq, AuthRefreshRes } from "@/apis/dto/auth";

const TIMEOUT = 30000; // 30초

export const axiosInstance = axios.create({
  // baseURL: process.env.NEXT_PUBLIC_APP_URL,
  timeout: TIMEOUT,
});

axiosInstance.interceptors.request.use((config) => {
  const token = Cookies.get("access-token");
  config.headers.Authorization = token ? `Bearer ${token}` : "";
  const reqId = uuidv4();
  config.headers["X-Request-ID"] = reqId;
  return config;
});

const axiosForRefreshToken = axios.create({
  baseURL: process.env.NEXT_PUBLIC_APP_URL,
  timeout: TIMEOUT,
});

const redirectToLogin = (nextUrl?: string) => {
  if (typeof window !== "undefined") {
    const currentUrlWithoutBase = window.location.href.replace(
      window.location.origin,
      "",
    );
    window.location.href = `/login?next=${encodeURIComponent(nextUrl || currentUrlWithoutBase)}`;
  }
};

// 응답 인터셉터
axiosInstance.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    if (typeof window === "undefined") return;
    console.error("error", error);
    /*토큰 만료되는 경우 (refresh token시도) */
    if (error.response?.data?.status === 401) {
      const { logout, refreshToken, setAccessToken } = useUserStore.getState();

      return refreshTokenAndRetry(error, {
        logout: () => logout(redirectToLogin),
        refreshToken,
        setAccessToken,
      });
    } else if (
      /*토큰이 무효한 경우 */
      error.response?.data?.status === 401 &&
      error?.response?.data?.message === "invalid-token"
    ) {
      Cookies.set("access-token", "", { expires: 0 });
      Cookies.set("refresh-token", "", { expires: 0 });
      return (window.location.href = "/");
    } else if (
      /*토큰이 변조되거나 읽을수 없는 경우 */
      error.response?.data?.status === 401 &&
      error?.response?.data?.message === "authentication error"
    ) {
      const { logout } = useUserStore.getState();
      logout(redirectToLogin);
    } else if (
      /*로그인 중복되는 경우 */
      error.response?.data?.status === 401 &&
      error?.response?.data?.message === "already logged in"
    ) {
      const { logout } = useUserStore.getState();

      logout(redirectToLogin);
    } else if (
      /*유저를 찾을수 없을때*/
      error.response?.data?.status === 401 &&
      error?.response?.data?.message === "invalid-token-user"
    ) {
      const { logout } = useUserStore.getState();

      logout(redirectToLogin);
    } else if (
      /*유저를 찾을수 없을때*/
      error.response?.data?.status === 401 &&
      (error?.response?.data?.message === "invalid-token-admin" ||
        error?.response?.data?.message === "invalid-token-type")
    ) {
      const { logout } = useUserStore.getState();

      logout(redirectToLogin);
    } else if (
      /*로그인 토큰을 안보냈을때*/
      error.response?.data?.status === 401 &&
      error?.response?.data?.message === "Login Required"
    ) {
      const currentUrlWithoutBase = window.location.href.replace(
        window.location.origin,
        "",
      );
      window.location.href = `/login?next=${encodeURIComponent(currentUrlWithoutBase)}`;
    }

    return Promise.reject(error);
  },
);

const refreshTokenAndRetry = async (
  error: AxiosError,
  { logout, refreshToken, setAccessToken }: StoreActions,
): Promise<AxiosResponse | undefined> => {
  const reqId = error.config?.headers["X-Request-ID"] || "";
  if (refreshToken) {
    try {
      const requestBody: AuthRefreshReq = {
        refreshToken: refreshToken,
      };
      const { data } = await axiosForRefreshToken.post<AuthRefreshRes>(
        requestBody.refreshToken,
      );
      setAccessToken(data.accessToken);
      if (error.config) {
        error.config.headers.Authorization = `Bearer ${data.accessToken}`;

        return axiosInstance.request(error.config);
      }
    } catch (e: any) {
      logout();
      // 오류 메시지 출력
      if (e.response?.data?.message === "token-expired") {
        console.error("refresh 토큰 만료");
      } else if (e.response?.data?.message === "invalid-token") {
        console.error("유효하지 않은 refresh 토큰");
      } else if (e instanceof Error) {
      } else if (e.response?.data?.message === "authentication-error") {
        console.error("기타 refresh token 오류");
      } else if (e instanceof Error) {
        console.error(
          `[reqId: ${reqId}] Refresh token failed: ${e.message} (Error Code: ${e.name || "UNKNOWN"})`,
        );
        return Promise.reject(new Error(`Refresh token failed: ${e.message}`));
      } else {
        console.error(`[reqId: ${reqId}] An unknown error occurred.`);
        return Promise.reject(new Error("An unknown error occurred."));
      }
    }
  }
  logout();
  return Promise.reject(
    new Error(`[reqId: ${reqId}] No refresh token available`),
  );
};

type StoreActions = {
  logout: () => void;
  refreshToken: string | null;
  setAccessToken: (token: string) => void;
};

export default axiosInstance;