// ���� ifdef ����� DLL���� ���������ϴ� �۾��� ���� �� �ִ� ��ũ�θ� ����� 
// ǥ�� ����Դϴ�. �� DLL�� ��� �ִ� ������ ��� ����ٿ� ���ǵ� _EXPORTS ��ȣ��
// �����ϵǸ�, �ٸ� ������Ʈ������ �� ��ȣ�� ������ �� �����ϴ�.
// �̷��� �ϸ� �ҽ� ���Ͽ� �� ������ ��� �ִ� �ٸ� ��� ������Ʈ������ 
// G3_API_LIBRARY_API �Լ��� DLL���� �������� ������ ����, �� DLL��
// �� DLL�� �ش� ��ũ�η� ���ǵ� ��ȣ�� ���������� ������ ���ϴ�.
#ifdef G3_API_LIBRARY_EXPORTS
#define G3_API_LIBRARY_API __declspec(dllexport)
#else
#define G3_API_LIBRARY_API __declspec(dllimport)
#endif

// �� Ŭ������ g3_api_library.dll���� ������ ���Դϴ�.
class G3_API_LIBRARY_API Cg3_api_library {
public:
	Cg3_api_library(void);
	// TODO: ���⿡ �޼��带 �߰��մϴ�.
};

extern G3_API_LIBRARY_API int ng3_api_library;

G3_API_LIBRARY_API int fng3_api_library(void);
